#!/bin/bash
echo "============================================================"
echo " FirmaEC PWA - Servidor local"
echo "============================================================"
echo ""

pip install flask flask-cors pyhanko pyhanko-certvalidator pypdf \
    reportlab "qrcode[pil]" pillow "cryptography>=42.0.8" -q

echo ""
echo "Iniciando servidor en http://localhost:5000"
echo "Abra su navegador en esa direccion."
echo "Presione Ctrl+C para detener."
echo ""

python3 app.py
