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

# Mostrar detalle técnico adicional (Impacto en el puntaje y Peso OWASP)
python3 http_headers_audit.py ejemplo.com -v
python3 http_headers_audit.py ejemplo.com --verbose
```

> El dominio debe ingresarse **sin protocolo** (ej: `ejemplo.com`, no `https://ejemplo.com`).

### Visualización 

Ejecución contra dominio example.com

<img width="1230" height="470" alt="image" src="https://github.com/user-attachments/assets/b002d584-d3ec-4e63-bcc5-e5877a1efc96" />

<img width="1912" height="1025" alt="image" src="https://github.com/user-attachments/assets/e38da0ad-83d9-4fad-bf98-fa4e89d00a5f" />

<img width="1918" height="434" alt="image" src="https://github.com/user-attachments/assets/d5eb3edd-4872-4391-b748-508a8608ff6f" />

<img width="1914" height="739" alt="image" src="https://github.com/user-attachments/assets/65e4bc24-e727-451b-9f99-6b65a1d788d5" />


### Modo verbose (`-v` / `--verbose`)

Por defecto, el escaneo **oculta** las columnas técnicas **Impacto** (en el puntaje) y
**Peso OWASP** (ponderación usada en el cálculo), para priorizar la lectura del
resultado y la recomendación. Para inspeccionar ese detalle (por ejemplo, para
auditar cómo se compone el puntaje) usa `-v` / `--verbose`, que las añade de
nuevo a las tablas de evaluación en consola y en el PDF.

## Salida

El script presenta en consola:

1. **Panel resumen** — nota (A+ a F), puntaje, estado HTTP, pruebas aprobadas/fallidas.
2. **Tabla de cabeceras HTTP recibidas** — todas las cabeceras devueltas por el servidor.
3. **Tabla de evaluación (tests de mdn-http-observatory)** — para cada control (CSP, HSTS, cookies, CORS, etc.):
   - Estado (CUMPLE / NO CUMPLE / N/A) con colores.
   - Resultado obtenido por la herramienta, con el máximo espacio posible dentro
     de la celda para que el texto siempre sea legible.
   - **Contra** — contra qué amenazas/vectores de ataque protege una configuración
     correcta de esa cabecera (ej: XSS, clickjacking, session hijacking, MiTM,
     supply chain, etc.), según las mismas guías OWASP usadas como base.
   - Valor recomendado por OWASP (en caso de no cumplimiento), también con el
     máximo espacio posible en la celda, con enlace directo a la sección
     correspondiente del Cheat Sheet.
   - Impacto en el puntaje y Peso OWASP — **ocultos por defecto**, visibles solo
     con `-v` / `--verbose`.
   - Cuando el resultado crudo de la herramienta indica que un control no aplica
     al modelo de negocio real del sitio (por ejemplo: no hay cookies, no se
     cargan scripts de terceros, o el sitio no atiende HTTP/HTTPS), el estado se
     marca como **N/A** y se añade una nota de "Contexto de negocio" explicando
     el motivo, en lugar de contarlo como una configuración correcta o incorrecta.
4. **Tabla de cabeceras adicionales (OWASP Cheat Sheet)** — controles que mdn-http-observatory no puntúa pero que OWASP sí recomienda revisar:
   - X-XSS-Protection (debería omitirse o valer `0`).
   - Permissions-Policy.
   - Cross-Origin-Opener-Policy (COOP).
   - Cross-Origin-Embedder-Policy (COEP).
   - Divulgación de información del servidor (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.).
   - Estas filas también incluyen la columna **Contra** y ocultan el Peso OWASP salvo con `-v`.
5. **Panel de referencia** — enlace a la guía OWASP y a la sección *Testing Proper Implementation of Security Headers*.
6. **Nota final sobre la puntuación** — ver aviso más abajo; se imprime siempre al final del reporte (consola y PDF).

## Aviso sobre la puntuación (importante)

- La nota (A+ a F) y el puntaje mostrados **no son un puntaje oficial de OWASP**.
  OWASP no emite calificaciones ni certificaciones de cabeceras HTTP; el cálculo
  es propio de este script y está **inspirado** en la importancia relativa que las
  guías de OWASP (Cheat Sheet Series) asignan a cada cabecera.
- **MDN HTTP Observatory** (la herramienta `mdn-http-observatory-scan` en la que
  se apoya este proyecto) es un **puntuador de configuración de cabeceras HTTP**.
  Se usa aquí como una **métrica de apoyo** dentro de la evaluación, y **no**
  como una medición global de la seguridad del sitio analizado: no evalúa
  vulnerabilidades como inyección SQL, componentes desactualizados, plugins de
  CMS vulnerables o malas prácticas de gestión de contraseñas, entre otras. Así
  lo indica la propia documentación de MDN
  ([FAQ del Observatory](https://developer.mozilla.org/en-US/observatory/docs/faq)).
  Este informe no sustituye pruebas de intrusión, revisión de código ni un
  análisis de seguridad integral.

## Referencia

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN HTTP Observatory](https://github.com/mdn/http-observatory)

## Archivos

| Archivo | Descripción |
|---|---|
| `http_headers_audit.py` | Script principal |
| `requirements.txt` | Dependencias Python |
| `README.md` | Este documento |
