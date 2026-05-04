#!/usr/bin/env python3
"""
FirmaEC PWA - Backend Flask
API REST para firma electrónica de PDFs con certificado P12.
"""

import base64
import io
import os
import tempfile
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

# ── Importar lógica de firma ──────────────────────────────────────
from pyhanko.sign import signers, fields
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.sign.signers import SimpleSigner
import asn1crypto.x509 as asn1x509
import asn1crypto.core as asn1core
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.utils import ImageReader
import qrcode
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates, serialize_key_and_certificates,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption,
)
from cryptography.x509.oid import NameOID
from cryptography.x509 import BasicConstraints

# ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)


@app.after_request
def agregar_cabeceras_pwa(response):
    """Agrega cabeceras necesarias para que la PWA sea instalable."""
    # Permite instalar la PWA en Chrome/Edge/Safari
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'

    # Cache: manifest y SW nunca se cachean en el navegador
    if request.path in ('/static/manifest.json', '/static/sw.js'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma']        = 'no-cache'
        response.headers['Expires']       = '0'

    # El Service Worker necesita content-type correcto
    if request.path == '/static/sw.js':
        response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        response.headers['Service-Worker-Allowed'] = '/'

    # Manifest
    if request.path == '/static/manifest.json':
        response.headers['Content-Type'] = 'application/manifest+json; charset=utf-8'

    return response


# Rutas explícitas para Service Worker y manifest (evita problemas de scope)
@app.route('/sw.js')
def service_worker():
    """Sirve el SW desde la raíz para que su scope sea '/'."""
    from flask import make_response, send_from_directory
    resp = make_response(send_from_directory('static', 'sw.js'))
    resp.headers['Content-Type']          = 'application/javascript; charset=utf-8'
    resp.headers['Cache-Control']         = 'no-cache, no-store, must-revalidate'
    resp.headers['Service-Worker-Allowed'] = '/'
    return resp


@app.route('/manifest.json')
def manifest():
    """Sirve el manifest desde la raíz."""
    from flask import make_response, send_from_directory
    resp = make_response(send_from_directory('static', 'manifest.json'))
    resp.headers['Content-Type']  = 'application/manifest+json; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

TZ_EC       = timezone(timedelta(hours=-5))
QR_PX       = 100
SELLO_PT_H  = 70
MARGEN_INF  = 14
PADDING_PX  = 10

_FUENTES_BOLD = [
    "C:/Windows/Fonts/arialbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]
_FUENTES_NORM = [
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


# ─────────────────────────────────────────────────────────────────
#  UTILIDADES
# ─────────────────────────────────────────────────────────────────

def ahora_ec():
    return datetime.now(TZ_EC)


def _cargar_fuente(rutas, size):
    for r in rutas:
        if os.path.isfile(r):
            try:
                return ImageFont.truetype(r, size)
            except Exception:
                continue
    return ImageFont.load_default()


def _cargar_p12(p12_bytes, contrasena):
    pwd = contrasena.encode("utf-8") if contrasena else None
    try:
        return load_key_and_certificates(p12_bytes, pwd)
    except TypeError:
        from cryptography.hazmat.backends import default_backend
        return load_key_and_certificates(p12_bytes, pwd, default_backend())


def _cn(cert):
    try:
        a = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return a[0].value if a else "Desconocido"
    except Exception:
        return "Desconocido"


def _serial_num(cert):
    try:
        a = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        return a[0].value if a else ""
    except Exception:
        return ""


def _fechas(cert):
    try:
        return cert.not_valid_before_utc.astimezone(TZ_EC), \
               cert.not_valid_after_utc.astimezone(TZ_EC)
    except AttributeError:
        return (cert.not_valid_before.replace(tzinfo=timezone.utc).astimezone(TZ_EC),
                cert.not_valid_after.replace(tzinfo=timezone.utc).astimezone(TZ_EC))


def _es_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(BasicConstraints).value.ca
    except Exception:
        return False


def _identidad_bce(cert):
    OID_BCE = {
        '1.3.6.1.4.1.37947.3.1': 'cedula',
        '1.3.6.1.4.1.37947.3.2': 'nombres',
    }
    campos = {}
    try:
        asn1_cert = asn1x509.Certificate.load(cert.public_bytes(Encoding.DER))
        for ext in asn1_cert['tbs_certificate']['extensions']:
            oid = ext['extn_id'].dotted
            if oid in OID_BCE:
                raw = bytes(ext['extn_value'].parsed.contents)
                try:
                    val = asn1core.Any.load(raw).native
                    if isinstance(val, bytes):
                        val = val.decode('utf-8', errors='replace').strip()
                except Exception:
                    val = raw.decode('utf-8', errors='replace').strip('\x00')
                campos[OID_BCE[oid]] = val
    except Exception:
        pass
    return campos


def _construir_signer(p12_bytes, contrasena):
    clave, cert_p, cadena = _cargar_p12(p12_bytes, contrasena)
    ahora = ahora_ec()
    cas_vigentes = [c for c in (cadena or [])
                    if _es_ca(c) and (_fechas(c)[0] <= ahora <= _fechas(c)[1])]
    p12_limpio = serialize_key_and_certificates(
        b"firmante", clave, cert_p,
        cas_vigentes or None,
        BestAvailableEncryption(b'_tmp_'),
    )
    return SimpleSigner.load_pkcs12_data(
        p12_limpio, other_certs=[], passphrase=b'_tmp_')


def generar_sello(nombre, fecha):
    contenido = (f"Firmado digitalmente por: {nombre}\n"
                 f"Fecha: {fecha}\nEstandar: PAdES - Ecuador")
    qr = qrcode.QRCode(version=2,
                       error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=3, border=1)
    qr.add_data(contenido)
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    img_qr = img_qr.resize((QR_PX, QR_PX), Image.LANCZOS)

    f_etiq = _cargar_fuente(_FUENTES_NORM, 11)
    f_nom  = _cargar_fuente(_FUENTES_BOLD, 13)
    f_fech = _cargar_fuente(_FUENTES_NORM, 11)

    dummy  = Image.new("RGB", (1, 1))
    dd     = ImageDraw.Draw(dummy)
    etiq   = "Firmado digitalmente por:"
    TEXT_W = int(max(dd.textlength(etiq, font=f_etiq),
                     dd.textlength(nombre, font=f_nom),
                     dd.textlength(fecha, font=f_fech))) + 12

    W = QR_PX + PADDING_PX + TEXT_W
    H = QR_PX
    img  = Image.new("RGB", (W, H), "white")
    img.paste(img_qr, (0, 0))
    draw = ImageDraw.Draw(img)
    draw.line([(QR_PX + 4, 6), (QR_PX + 4, H - 6)], fill="#cccccc", width=1)
    LINE_H  = 17
    x_txt   = QR_PX + PADDING_PX
    y_start = (H - LINE_H * 3) // 2
    draw.text((x_txt, y_start),              etiq,   fill="#555555", font=f_etiq)
    draw.text((x_txt, y_start + LINE_H),     nombre, fill="#000000", font=f_nom)
    draw.text((x_txt, y_start + LINE_H * 2), fecha,  fill="#333333", font=f_fech)
    return img


def insertar_sello(pdf_bytes, nombre, fecha):
    img_sello = generar_sello(nombre, fecha)
    reader    = PdfReader(io.BytesIO(pdf_bytes))
    writer    = PdfWriter()
    for pagina in reader.pages:
        ancho = float(pagina.mediabox.width)
        alto  = float(pagina.mediabox.height)
        ratio = img_sello.width / img_sello.height
        h_pt  = SELLO_PT_H
        w_pt  = h_pt * ratio
        x     = (ancho - w_pt) / 2
        buf   = io.BytesIO()
        c     = rl_canvas.Canvas(buf, pagesize=(ancho, alto))
        ib    = io.BytesIO()
        img_sello.save(ib, format="PNG")
        ib.seek(0)
        c.drawImage(ImageReader(ib), x=x, y=MARGEN_INF,
                    width=w_pt, height=h_pt,
                    preserveAspectRatio=True, mask="auto")
        c.save()
        buf.seek(0)
        ov = PdfReader(io.BytesIO(buf.read())).pages[0]
        pagina.merge_page(ov)
        writer.add_page(pagina)
    if reader.metadata:
        writer.add_metadata(reader.metadata)
    salida = io.BytesIO()
    writer.write(salida)
    return salida.getvalue()


def aplicar_firma(pdf_bytes, p12_bytes, contrasena, nombre, cedula):
    signer = _construir_signer(p12_bytes, contrasena)
    meta = PdfSignatureMetadata(
        field_name="FirmaDigitalEC",
        name=nombre,
        reason=f"Firmado por {nombre}",
        location="Ecuador",
        contact_info=cedula,
        certify=False,
        subfilter=SigSeedSubFilter.PADES,
    )
    pdf_in = io.BytesIO(pdf_bytes)
    writer = IncrementalPdfFileWriter(pdf_in)
    fields.append_signature_field(
        writer,
        SigFieldSpec(sig_field_name="FirmaDigitalEC",
                     on_page=0, box=(0, 0, 0, 0)),
    )
    resultado = signers.sign_pdf(writer, signature_meta=meta, signer=signer)
    return resultado.read()


# ─────────────────────────────────────────────────────────────────
#  RUTAS API
# ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/verificar-cert", methods=["POST"])
def verificar_cert():
    """Verifica el certificado P12 y retorna sus datos."""
    try:
        p12_b64  = request.json.get("p12_b64", "")
        password = request.json.get("password", "")
        p12_bytes = base64.b64decode(p12_b64)

        clave, cert, cadena = _cargar_p12(p12_bytes, password)
        ahora = ahora_ec()
        emi, exp = _fechas(cert)
        vigente  = emi <= ahora <= exp
        dias     = (exp - ahora).days

        identidad = _identidad_bce(cert)
        cedula    = identidad.get("cedula", _serial_num(cert))

        issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        emisor = issuer_attrs[0].value if issuer_attrs else "Desconocido"

        cert_cadena = any(
            _cn(c) == _cn(cert) and not _es_ca(c) and
            (_fechas(c)[0] <= ahora <= _fechas(c)[1])
            for c in (cadena or [])
        )

        cas = [
            {
                "cn":      _cn(c),
                "expira":  _fechas(c)[1].strftime("%d/%m/%Y"),
                "vigente": _fechas(c)[0] <= ahora <= _fechas(c)[1],
                "es_ca":   _es_ca(c),
            }
            for c in (cadena or [])
        ]

        return jsonify({
            "ok":          True,
            "cn":          _cn(cert),
            "cedula":      cedula,
            "emisor":      emisor,
            "emision":     emi.strftime("%d/%m/%Y"),
            "expiracion":  exp.strftime("%d/%m/%Y"),
            "vigente":     vigente,
            "dias":        dias,
            "cert_cadena": cert_cadena,
            "cadena":      cas,
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/firmar", methods=["POST"])
def firmar():
    """
    Firma uno o más PDFs.
    Recibe JSON: { p12_b64, password, archivos: [{nombre, pdf_b64}] }
    Retorna JSON: { resultados: [{nombre, firmado_b64, error}] }
    """
    try:
        data     = request.json
        p12_b64  = data.get("p12_b64", "")
        password = data.get("password", "")
        archivos = data.get("archivos", [])

        p12_bytes = base64.b64decode(p12_b64)

        # Obtener datos del firmante
        clave, cert, cadena = _cargar_p12(p12_bytes, password)
        nombre   = _cn(cert)
        identidad = _identidad_bce(cert)
        cedula   = identidad.get("cedula", _serial_num(cert))
        fecha    = ahora_ec().strftime("%d/%m/%Y %H:%M:%S")

        resultados = []
        for archivo in archivos:
            nombre_pdf = archivo.get("nombre", "documento.pdf")
            try:
                pdf_bytes = base64.b64decode(archivo.get("pdf_b64", ""))

                # 1. Insertar sello visual
                pdf_sellado = insertar_sello(pdf_bytes, nombre, fecha)

                # 2. Firma PAdES
                pdf_firmado = aplicar_firma(
                    pdf_sellado, p12_bytes, password, nombre, cedula)

                # Nombre de salida
                stem   = Path(nombre_pdf).stem
                nombre_out = f"{stem}_firmado.pdf"

                resultados.append({
                    "nombre":     nombre_out,
                    "firmado_b64": base64.b64encode(pdf_firmado).decode(),
                    "error":      None,
                })
            except Exception as e:
                resultados.append({
                    "nombre": nombre_pdf,
                    "firmado_b64": None,
                    "error": str(e),
                })

        return jsonify({
            "ok":         True,
            "firmante":   nombre,
            "cedula":     cedula,
            "fecha":      fecha,
            "resultados": resultados,
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/estado")
def estado():
    return jsonify({"ok": True, "version": "1.0.0", "servicio": "FirmaEC PWA"})


# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  FirmaEC PWA corriendo en http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
