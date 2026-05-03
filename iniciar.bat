@echo off
echo ============================================================
echo  FirmaEC PWA - Servidor local
echo ============================================================
echo.

python --version 2>nul
if errorlevel 1 (
    echo ERROR: Python no esta instalado.
    pause
    exit /b 1
)

echo Instalando dependencias...
python -m pip install flask flask-cors pyhanko pyhanko-certvalidator pypdf ^
    reportlab "qrcode[pil]" pillow "cryptography>=42.0.8" --quiet

echo.
echo Iniciando servidor en http://localhost:5000
echo Abra su navegador en esa direccion.
echo Presione Ctrl+C para detener el servidor.
echo.

python app.py

pause
