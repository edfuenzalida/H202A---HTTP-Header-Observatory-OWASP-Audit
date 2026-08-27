#!/usr/bin/env python3
"""
http_headers_audit.py

Integra la herramienta 'mdn-http-observatory-scan' (npm, @mdn/mdn-http-observatory)
para evaluar las cabeceras de seguridad HTTP de un dominio y presenta los
resultados en un panel de consola, alineado a las recomendaciones del
OWASP HTTP Headers Cheat Sheet:
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Uso:
    python3 http_headers_audit.py <dominio> [--json-out salida.json] [--headers '{"X-Foo":"bar"}']

Requisitos:
    - Node.js / npm con 'mdn-http-observatory-scan' instalado (npm i -g @mdn/mdn-http-observatory
      o disponible como binario 'mdn-http-observatory-scan' en el PATH).
    - Paquete Python 'rich' (pip install rich).
"""

import argparse
import json
import shutil
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

CLI_BIN = "mdn-http-observatory-scan"

OWASP_CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
)

# Mapeo de cada test de mdn-http-observatory hacia la sección/ancla
# correspondiente del OWASP HTTP Headers Cheat Sheet.
# (mdn-http-observatory-scan solo ejecuta estos 10 tests; ver
# src/analyzer/tests/*.js del paquete @mdn/mdn-http-observatory)
OWASP_HEADER_LINKS = {
    "content-security-policy": OWASP_CHEATSHEET_URL + "#content-security-policy-csp",
    "cookies": OWASP_CHEATSHEET_URL + "#set-cookie",
    "cross-origin-resource-sharing": OWASP_CHEATSHEET_URL + "#access-control-allow-origin",
    "redirection": OWASP_CHEATSHEET_URL + "#strict-transport-security-hsts",
    "referrer-policy": OWASP_CHEATSHEET_URL + "#referrer-policy",
    "strict-transport-security": OWASP_CHEATSHEET_URL + "#strict-transport-security-hsts",
    "subresource-integrity": OWASP_CHEATSHEET_URL + "#recommendation",
    "x-content-type-options": OWASP_CHEATSHEET_URL + "#x-content-type-options",
    "x-frame-options": OWASP_CHEATSHEET_URL + "#x-frame-options",
    "cross-origin-resource-policy": OWASP_CHEATSHEET_URL + "#cross-origin-resource-policy-corp",
}

# Nombres legibles para cada test.
TEST_LABELS = {
    "content-security-policy": "Content-Security-Policy",
    "cookies": "Cookies (Secure / HttpOnly / SameSite)",
    "cross-origin-resource-sharing": "Cross-Origin Resource Sharing (CORS)",
    "redirection": "Redirección a HTTPS",
    "referrer-policy": "Referrer-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "subresource-integrity": "Subresource Integrity (SRI)",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy (CORP)",
}

# Valor / configuración recomendada por el OWASP HTTP Headers Cheat Sheet
# para cada test cubierto por mdn-http-observatory-scan.
RECOMMENDED_VALUES = {
    "content-security-policy": (
        "Definir una política restrictiva sin 'unsafe-inline' ni 'unsafe-eval' "
        "(ver Content Security Policy Cheat Sheet)."
    ),
    "cookies": "Set-Cookie con Secure, HttpOnly y SameSite=Strict/Lax en cookies de sesión.",
    "cross-origin-resource-sharing": (
        "Access-Control-Allow-Origin con orígenes específicos; evitar '*' junto a credenciales."
    ),
    "redirection": "Redirigir todo el tráfico HTTP a HTTPS antes de servir contenido.",
    "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "strict-transport-security": (
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
    ),
    "subresource-integrity": (
        "Usar el atributo 'integrity' en <script>/<link> que carguen recursos de terceros."
    ),
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "x-frame-options": (
        "Usar CSP 'frame-ancestors' si es posible; en su defecto, X-Frame-Options: DENY"
    ),
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy: same-site",
}

# Cabeceras adicionales recomendadas por el OWASP HTTP Headers Cheat Sheet
# que mdn-http-observatory-scan NO evalúa como "tests" (no aportan
# scoreModifier), pero que la guía sí revisa explícitamente. Cada entrada
# es una función (response_headers) -> (pass: bool, detalle: str).
def _check_x_xss_protection(headers):
    value = headers.get("x-xss-protection")
    if value is None:
        return True, "No está presente (recomendado: omitir o usar '0')."
    if value.strip() == "0":
        return True, f"Presente con valor seguro: '{value}'."
    return False, f"Presente con valor '{value}'; puede introducir vulnerabilidades de XSS."


def _check_permissions_policy(headers):
    value = headers.get("permissions-policy")
    if value:
        return True, f"Presente: '{value}'."
    return False, "No está presente; no se restringen APIs del navegador (cámara, geolocalización, etc.)."


def _check_coop(headers):
    value = headers.get("cross-origin-opener-policy")
    if value:
        return True, f"Presente: '{value}'."
    return False, "No está presente; recomendado 'same-origin' para aislar el contexto de navegación."


def _check_coep(headers):
    value = headers.get("cross-origin-embedder-policy")
    if value:
        return True, f"Presente: '{value}'."
    return False, "No está presente; recomendado 'require-corp' si la app usa aislamiento de origen cruzado."


def _check_info_disclosure(headers):
    disclosed = []
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = headers.get(h)
        if value:
            disclosed.append(f"{h}: {value}")
    if disclosed:
        return False, "Cabeceras con información del servidor expuesta -> " + "; ".join(disclosed)
    return True, "No se detectan cabeceras que revelen tecnología/versión del servidor."


EXTRA_CHECKS = {
    "X-XSS-Protection": (_check_x_xss_protection, OWASP_CHEATSHEET_URL + "#x-xss-protection"),
    "Permissions-Policy": (_check_permissions_policy, OWASP_CHEATSHEET_URL + "#permissions-policy-formerly-feature-policy"),
    "Cross-Origin-Opener-Policy (COOP)": (_check_coop, OWASP_CHEATSHEET_URL + "#cross-origin-opener-policy-coop"),
    "Cross-Origin-Embedder-Policy (COEP)": (_check_coep, OWASP_CHEATSHEET_URL + "#cross-origin-embedder-policy-coep"),
    "Divulgación de información del servidor": (
        _check_info_disclosure,
        OWASP_CHEATSHEET_URL + "#server",
    ),
}


GRADE_COLORS = {
    "A+": "bright_green",
    "A": "bright_green",
    "A-": "green",
    "B+": "green",
    "B": "yellow",
    "B-": "yellow",
    "C+": "yellow",
    "C": "dark_orange",
    "C-": "dark_orange",
    "D+": "red",
    "D": "red",
    "D-": "red",
    "F": "bright_red",
}


def run_scan(hostname, headers, send_headers_over_http):
    """Ejecuta mdn-http-observatory-scan y devuelve el JSON resultante."""
    if shutil.which(CLI_BIN) is None:
        console = Console(stderr=True)
        console.print(
            f"[bold red]Error:[/bold red] no se encontró el binario '{CLI_BIN}' en el PATH.\n"
            f"Instálalo con: [cyan]npm install -g @mdn/mdn-http-observatory[/cyan]"
        )
        sys.exit(1)

    cmd = [CLI_BIN, hostname]
    if headers:
        cmd += ["--headers", headers]
    if send_headers_over_http:
        cmd.append("--send-headers-over-http")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        Console(stderr=True).print("[bold red]Error:[/bold red] tiempo de espera agotado ejecutando el escaneo.")
        sys.exit(1)

    stdout = result.stdout.strip()

    if result.returncode != 0:
        # mdn-http-observatory-scan devuelve el detalle del fallo como JSON
        # en stdout (ej: {"error":"The site seems to be down."}) aunque
        # termine con código de salida distinto de 0.
        if stdout:
            try:
                payload = json.loads(stdout)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict) and "error" in payload:
                Console(stderr=True).print(
                    f"[bold red]No se pudo completar el escaneo de '{hostname}':[/bold red] "
                    f"{payload['error']}"
                )
                sys.exit(1)
        Console(stderr=True).print(
            f"[bold red]Error al ejecutar {CLI_BIN}:[/bold red]\n"
            f"{result.stderr.strip() or stdout or '(sin detalle devuelto por la herramienta)'}"
        )
        sys.exit(1)

    if not stdout:
        Console(stderr=True).print("[bold red]Error:[/bold red] la herramienta no devolvió salida.")
        sys.exit(1)

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        Console(stderr=True).print(
            "[bold red]Error:[/bold red] no se pudo interpretar la salida como JSON."
        )
        Console(stderr=True).print(stdout)
        sys.exit(1)


def grade_color(grade):
    return GRADE_COLORS.get(grade, "white")


def score_color(score):
    if score >= 90:
        return "bright_green"
    if score >= 70:
        return "yellow"
    if score >= 50:
        return "dark_orange"
    return "bright_red"


def build_summary_panel(hostname, scan):
    grade = scan.get("grade", "N/A")
    score = scan.get("score", 0)
    status_code = scan.get("statusCode", "N/A")
    passed = scan.get("testsPassed", 0)
    failed = scan.get("testsFailed", 0)
    total = scan.get("testsQuantity", passed + failed)
    error = scan.get("error")

    g_color = grade_color(grade)
    s_color = score_color(score)

    body = Text()
    body.append("Dominio: ", style="bold")
    body.append(f"{hostname}\n", style="cyan")
    body.append("Nota:    ", style="bold")
    body.append(f"{grade}", style=f"bold {g_color}")
    body.append("   Puntaje: ", style="bold")
    body.append(f"{score}/100\n", style=f"bold {s_color}")
    body.append("Estado HTTP: ", style="bold")
    body.append(f"{status_code}\n")
    body.append("Pruebas: ", style="bold")
    body.append(f"{passed} aprobadas", style="bright_green")
    body.append(" / ")
    body.append(f"{failed} fallidas", style="bright_red" if failed else "bright_green")
    body.append(f" (total {total})\n")
    if error:
        body.append("Error del escaneo: ", style="bold red")
        body.append(f"{error}\n", style="red")

    return Panel(
        body,
        title="[bold]Resumen del escaneo HTTP Observatory[/bold]",
        border_style=g_color,
        box=box.ROUNDED,
    )


def build_headers_table(response_headers):
    table = Table(
        title="Cabeceras HTTP recibidas",
        box=box.SIMPLE_HEAVY,
        header_style="bold blue",
        show_lines=False,
    )
    table.add_column("Cabecera", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")
    for key, value in sorted(response_headers.items()):
        table.add_row(key, str(value))
    return table


def build_tests_table(tests):
    table = Table(
        title="Evaluación de cabeceras de seguridad (OWASP HTTP Headers Cheat Sheet)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    table.add_column("Cabecera / Control", style="bold", ratio=2)
    table.add_column("Estado", justify="center", ratio=1)
    table.add_column("Resultado obtenido", ratio=2)
    table.add_column("Impacto", justify="center", ratio=1)
    table.add_column("Recomendación OWASP", ratio=4)

    ordered_keys = sorted(tests.keys(), key=lambda k: (tests[k].get("pass") is True, k))

    for key in ordered_keys:
        test = tests[key]
        label = TEST_LABELS.get(key, key)
        passed = test.get("pass")
        modifier = test.get("scoreModifier", 0)
        result = test.get("result", "N/A")
        link = OWASP_HEADER_LINKS.get(key, OWASP_CHEATSHEET_URL)
        recomendado = RECOMMENDED_VALUES.get(key, "Ver guía OWASP.")

        if passed is True:
            status = Text("CUMPLE", style="bold bright_green")
            recomendacion = Text()
            recomendacion.append("Conforme a OWASP.\n", style="green")
            recomendacion.append(link, style="underline bright_cyan")
        elif passed is False:
            status = Text("NO CUMPLE", style="bold bright_red")
            recomendacion = Text()
            recomendacion.append(f"{recomendado}\n", style="yellow")
            recomendacion.append(link, style="underline bright_cyan")
        else:
            status = Text("N/A", style="bold grey62")
            recomendacion = Text("Sin evaluación aplicable.", style="grey62")

        impact_style = "bright_green" if modifier > 0 else ("bright_red" if modifier < 0 else "grey62")
        impact_text = Text(f"{modifier:+d}" if modifier else "0", style=impact_style)

        table.add_row(label, status, str(result), impact_text, recomendacion)

    return table


def build_extra_checks_table(response_headers):
    """Cabeceras del OWASP HTTP Headers Cheat Sheet que mdn-http-observatory-scan
    no puntúa como test formal, evaluadas directamente sobre las cabeceras crudas."""
    table = Table(
        title="Cabeceras adicionales según OWASP Cheat Sheet (no puntuadas por mdn-http-observatory)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    table.add_column("Cabecera / Control", style="bold", ratio=2)
    table.add_column("Estado", justify="center", ratio=1)
    table.add_column("Detalle", ratio=3)
    table.add_column("Referencia OWASP", ratio=3)

    normalized = {k.lower(): v for k, v in response_headers.items()}

    for label, (check_fn, link) in EXTRA_CHECKS.items():
        ok, detail = check_fn(normalized)
        if ok:
            status = Text("CUMPLE", style="bold bright_green")
            ref = Text(link, style="underline bright_cyan")
        else:
            status = Text("REVISAR", style="bold bright_red")
            ref = Text(link, style="underline bright_cyan")
        table.add_row(label, status, detail, ref)

    return table


def build_reference_panel():
    body = Text()
    body.append("Guía de referencia utilizada:\n", style="bold")
    body.append("OWASP HTTP Headers Cheat Sheet\n", style="bold cyan")
    body.append(OWASP_CHEATSHEET_URL + "\n", style="underline bright_cyan")
    body.append(
        "Sección: Testing Proper Implementation of Security Headers -> ", style="italic"
    )
    body.append(OWASP_CHEATSHEET_URL + "#testing-proper-implementation-of-security-headers", style="underline bright_cyan")
    return Panel(body, border_style="blue", box=box.ROUNDED)


def render_report(hostname, data, console):
    scan = data.get("scan", {})
    tests = data.get("tests", {})
    response_headers = scan.get("responseHeaders", {})

    console.rule(f"[bold blue]Auditoría de cabeceras de seguridad HTTP — {hostname}[/bold blue]")
    console.print(build_summary_panel(hostname, scan))
    console.print()
    if response_headers:
        console.print(build_headers_table(response_headers))
        console.print()
    if tests:
        console.print(build_tests_table(tests))
        console.print()
    if response_headers:
        console.print(build_extra_checks_table(response_headers))
        console.print()
    console.print(build_reference_panel())


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audita las cabeceras de seguridad HTTP de un dominio usando "
                     "mdn-http-observatory-scan y las evalúa según el OWASP HTTP Headers Cheat Sheet."
    )
    parser.add_argument("dominio", help="Dominio o host a escanear (ej: ejemplo.com)")
    parser.add_argument(
        "--headers",
        help='Cabeceras personalizadas a enviar, en formato JSON (ej: \'{"X-Foo":"bar"}\')',
        default=None,
    )
    parser.add_argument(
        "--send-headers-over-http",
        action="store_true",
        help="Enviar también las cabeceras personalizadas por HTTP sin cifrar",
    )
    parser.add_argument(
        "--json-out",
        help="Ruta donde guardar el JSON crudo devuelto por mdn-http-observatory-scan",
        default=None,
    )
    return parser.parse_args()


def main():
    args = parse_args()
    console = Console()

    with console.status(f"[bold cyan]Escaneando {args.dominio}...[/bold cyan]"):
        data = run_scan(args.dominio, args.headers, args.send_headers_over_http)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green]JSON crudo guardado en:[/green] {args.json_out}")

    render_report(args.dominio, data, console)


if __name__ == "__main__":
    main()
