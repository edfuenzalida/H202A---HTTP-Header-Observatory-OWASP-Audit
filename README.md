# HTTP Headers Security Audit

Herramienta de línea de comandos que audita las cabeceras de seguridad HTTP de un dominio, integrando `mdn-http-observatory-scan` (MDN HTTP Observatory) y evaluando los resultados contra las recomendaciones del **OWASP HTTP Headers Cheat Sheet**.

## Requisitos

- **Python** >= 3.8
- **Node.js** >= 16 y **npm** >= 8
- **@mdn/mdn-http-observatory** (proporciona el binario `mdn-http-observatory-scan`)
- **Paquete Python `rich`** >= 13.0.0

## Instalación

```bash
# 1. Clonar el repositorio
git clone <URL_DEL_REPOSITORIO>
cd securityHeadersHTTPScan

# 2. Instalar dependencias de Node.js (mdn-http-observatory-scan)
npm install -g @mdn/mdn-http-observatory

# 3. Instalar dependencias de Python
pip install -r requirements.txt
```

> **Nota:** si no deseas instalar el paquete npm de forma global, puedes usar `npx`:
> ```bash
> npx @mdn/mdn-http-observatory --help
> ```
> En ese caso, edita la constante `CLI_BIN` en `http_headers_audit.py` apuntando al binario local.

## Uso

```bash
# Auditoría básica
python3 http_headers_audit.py ejemplo.com

# Guardar el JSON crudo devuelto por mdn-http-observatory-scan
python3 http_headers_audit.py ejemplo.com --json-out resultado.json

# Enviar cabeceras personalizadas en la petición (JSON)
python3 http_headers_audit.py ejemplo.com --headers '{"Authorization":"Bearer token"}'

# Enviar cabeceras personalizadas también por HTTP (sin cifrar)
python3 http_headers_audit.py ejemplo.com --headers '{"X-Debug":"1"}' --send-headers-over-http
```

> El dominio debe ingresarse **sin protocolo** (ej: `ejemplo.com`, no `https://ejemplo.com`).

## Salida

El script presenta en consola:

1. **Panel resumen** — nota (A+ a F), puntaje, estado HTTP, pruebas aprobadas/fallidas.
2. **Tabla de cabeceras HTTP recibidas** — todas las cabeceras devueltas por el servidor.
3. **Tabla de evaluación (tests de mdn-http-observatory)** — para cada control (CSP, HSTS, cookies, CORS, etc.):
   - Estado (CUMPLE / NO CUMPLE) con colores.
   - Resultado obtenido por la herramienta.
   - Impacto en el puntaje.
   - Valor recomendado por OWASP (en caso de no cumplimiento) con enlace directo a la sección correspondiente del Cheat Sheet.
4. **Tabla de cabeceras adicionales (OWASP Cheat Sheet)** — controles que mdn-http-observatory no puntúa pero que OWASP sí recomienda revisar:
   - X-XSS-Protection (debería omitirse o valer `0`).
   - Permissions-Policy.
   - Cross-Origin-Opener-Policy (COOP).
   - Cross-Origin-Embedder-Policy (COEP).
   - Divulgación de información del servidor (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.).
5. **Panel de referencia** — enlace a la guía OWASP y a la sección *Testing Proper Implementation of Security Headers*.

## Referencia

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN HTTP Observatory](https://github.com/mdn/http-observatory)

## Archivos

| Archivo | Descripción |
|---|---|
| `http_headers_audit.py` | Script principal |
| `requirements.txt` | Dependencias Python |
| `README.md` | Este documento |
