#!/usr/bin/env python3
"""
http_headers_audit.py

Integra la herramienta 'mdn-http-observatory-scan' (npm, @mdn/mdn-http-observatory)
para evaluar las cabeceras de seguridad HTTP de un dominio y presenta los
resultados en un panel de consola, alineado a las recomendaciones del
OWASP Cheat Sheet Series.

A diferencia del puntaje nativo de Observatory (basado en scoreModifier),
este script recalcula una puntuación propia ponderada según la importancia
que OWASP otorga a cada cabecera (ver OWASP_WEIGHTS).

Uso:
    python3 http_headers_audit.py <dominio> [--json-out salida.json]
        [--pdf-out informe.pdf] [--headers '{"X-Foo":"bar"}']

Requisitos:
    - Node.js / npm con 'mdn-http-observatory-scan' instalado (npm i -g @mdn/mdn-http-observatory
      o disponible como binario 'mdn-http-observatory-scan' en el PATH).
    - Paquete Python 'rich' (pip install rich).
    - Paquete Python 'reportlab' (pip install reportlab) SOLO si se usa --pdf-out.
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

# Cheat Sheet principal de cabeceras HTTP (se usa como base y para los
# controles que no tienen un artículo OWASP dedicado).
OWASP_CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
)

# Artículos OWASP dedicados (Cheat Sheet Series) para cada cabecera.
# Se usan URLs directas al artículo preciso en lugar de redirigir al índice.
OWASP_ARTICLE_URLS = {
    "content-security-policy": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
    ),
    "cookies": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
    ),
    "redirection": (
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
    ),
    "strict-transport-security": (
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
    ),
    "subresource-integrity": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html"
    ),
    "x-frame-options": (
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
    ),
}

# Mapeo de cada test de mdn-http-observatory hacia el artículo/ancla OWASP
# correspondiente. Cuando existe un artículo dedicado se usa ese; en caso
# contrario se apunta al ancla exacta del HTTP Headers Cheat Sheet.
# (mdn-http-observatory-scan solo ejecuta estos 10 tests; ver
# src/analyzer/tests/*.js del paquete @mdn/mdn-http-observatory)
OWASP_HEADER_LINKS = {
    "content-security-policy": OWASP_ARTICLE_URLS["content-security-policy"],
    "cookies": OWASP_ARTICLE_URLS["cookies"],
    "cross-origin-resource-sharing": OWASP_CHEATSHEET_URL + "#access-control-allow-origin",
    "redirection": OWASP_ARTICLE_URLS["redirection"],
    "referrer-policy": OWASP_CHEATSHEET_URL + "#referrer-policy",
    "strict-transport-security": OWASP_ARTICLE_URLS["strict-transport-security"],
    "subresource-integrity": OWASP_ARTICLE_URLS["subresource-integrity"],
    "x-content-type-options": OWASP_CHEATSHEET_URL + "#x-content-type-options",
    "x-frame-options": OWASP_ARTICLE_URLS["x-frame-options"],
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

# Valor / configuración recomendada por OWASP para cada test cubierto por
# mdn-http-observatory-scan.
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

# Peso (importancia) que OWASP otorga a cada control para el cálculo del
# puntaje propio. Escala 1 (menor) a 5 (crítico). Incluye tanto los tests
# formales de mdn-http-observatory como los controles adicionales.
OWASP_WEIGHTS = {
    "content-security-policy": 5,
    "strict-transport-security": 5,
    "cookies": 5,
    "redirection": 5,
    "x-content-type-options": 3,
    "x-frame-options": 3,
    "referrer-policy": 3,
    "cross-origin-resource-sharing": 3,
    "cross-origin-resource-policy": 3,
    "subresource-integrity": 2,
    "Permissions-Policy": 3,
    "Cross-Origin-Opener-Policy (COOP)": 3,
    "Cross-Origin-Embedder-Policy (COEP)": 2,
    "X-XSS-Protection": 1,
    "Divulgación de información del servidor": 3,
}

# Cabeceras adicionales recomendadas por OWASP que mdn-http-observatory-scan
# NO evalúa como "tests" (no aportan scoreModifier), pero que la guía sí
# revisa explícitamente. Cada entrada es una función
# (response_headers) -> (pass: bool, detalle: str).
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


def owasp_grade(score):
    """Traduce el puntaje OWASP (0-100) a una nota alfabética."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def collect_checks(tests, response_headers):
    """Reúne todos los controles (tests formales + adicionales) en una lista
    unificada de dicts con: key, label, passed, weight, result,
    recommendation, link, modifier."""
    formal = []
    for key in sorted(tests.keys()):
        test = tests[key]
        formal.append({
            "key": key,
            "label": TEST_LABELS.get(key, key),
            "passed": test.get("pass"),
            "weight": OWASP_WEIGHTS.get(key, 1),
            "result": test.get("result", "N/A"),
            "recommendation": RECOMMENDED_VALUES.get(key, "Ver guía OWASP."),
            "link": OWASP_HEADER_LINKS.get(key, OWASP_CHEATSHEET_URL),
            "modifier": test.get("scoreModifier", 0),
        })

    extra = []
    normalized = {k.lower(): v for k, v in response_headers.items()}
    for label, (check_fn, link) in EXTRA_CHECKS.items():
        ok, detail = check_fn(normalized)
        extra.append({
            "key": label,
            "label": label,
            "passed": ok,
            "weight": OWASP_WEIGHTS.get(label, 1),
            "result": detail,
            "recommendation": RECOMMENDED_VALUES.get(label, "Ver guía OWASP."),
            "link": link,
            "modifier": 0,
        })

    return formal, extra


def compute_owasp_score(checks):
    """Puntaje OWASP ponderado: 100 * (peso de controles que cumplen) /
    (peso total de controles aplicables). Los controles 'N/A' se excluyen."""
    applicable = [c for c in checks if c["passed"] is not None]
    if not applicable:
        return 0, 0
    total_weight = sum(c["weight"] for c in applicable)
    earned = sum(c["weight"] for c in applicable if c["passed"])
    score = round(100 * earned / total_weight)
    return score, total_weight


def build_summary_panel(hostname, scan, owasp_score, owasp_grade):
    status_code = scan.get("statusCode", "N/A")
    passed = scan.get("testsPassed", 0)
    failed = scan.get("testsFailed", 0)
    total = scan.get("testsQuantity", passed + failed)
    error = scan.get("error")

    obs_grade = scan.get("grade", "N/A")
    obs_score = scan.get("score", 0)

    g_color = grade_color(owasp_grade)
    s_color = score_color(owasp_score)

    body = Text()
    body.append("Dominio: ", style="bold")
    body.append(f"{hostname}\n", style="cyan")
    body.append("Nota OWASP: ", style="bold")
    body.append(f"{owasp_grade}", style=f"bold {g_color}")
    body.append("   Puntaje OWASP: ", style="bold")
    body.append(f"{owasp_score}/100\n", style=f"bold {s_color}")
    body.append("Puntaje Observatory (referencia): ", style="bold")
    body.append(f"{obs_score}/100 ({obs_grade})\n", style=grade_color(obs_grade))
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
        title="[bold]Resumen del escaneo (puntuación OWASP)[/bold]",
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


def build_tests_table(checks):
    table = Table(
        title="Evaluación de cabeceras de seguridad (OWASP Cheat Sheet Series)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    table.add_column("Cabecera / Control", style="bold", ratio=2)
    table.add_column("Estado", justify="center", ratio=1)
    table.add_column("Resultado obtenido", ratio=2)
    table.add_column("Impacto", justify="center", ratio=1)
    table.add_column("Peso OWASP", justify="center", ratio=1)
    table.add_column("Recomendación OWASP", ratio=4)

    ordered = sorted(checks, key=lambda c: (c["passed"] is True, c["label"]))

    for c in ordered:
        passed = c["passed"]
        label = c["label"]
        modifier = c["modifier"]
        result = c["result"]
        link = c["link"]
        recomendado = c["recommendation"]
        weight = c["weight"]

        if passed is True:
            status = Text("CUMPLE", style="bold bright_green")
            recomendacion = Text.from_markup(
                f"Conforme a OWASP.\n[link={link}]{link}[/link]",
                style="green",
            )
        elif passed is False:
            status = Text("NO CUMPLE", style="bold bright_red")
            recomendacion = Text.from_markup(
                f"{recomendado}\n[link={link}]{link}[/link]",
                style="yellow",
            )
        else:
            status = Text("N/A", style="bold grey62")
            recomendacion = Text("Sin evaluación aplicable.", style="grey62")

        impact_style = "bright_green" if modifier > 0 else ("bright_red" if modifier < 0 else "grey62")
        impact_text = Text(f"{modifier:+d}" if modifier else "0", style=impact_style)

        table.add_row(label, status, str(result), impact_text, str(weight), recomendacion)

    return table


def build_extra_checks_table(checks):
    """Cabeceras del OWASP HTTP Headers Cheat Sheet que mdn-http-observatory-scan
    no puntúa como test formal, evaluadas directamente sobre las cabeceras crudas."""
    table = Table(
        title="Cabeceras adicionales según OWASP (no puntuadas por mdn-http-observatory)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    table.add_column("Cabecera / Control", style="bold", ratio=2)
    table.add_column("Estado", justify="center", ratio=1)
    table.add_column("Detalle", ratio=3)
    table.add_column("Peso OWASP", justify="center", ratio=1)
    table.add_column("Referencia OWASP", ratio=3)

    for c in checks:
        ok = c["passed"]
        label = c["label"]
        detail = c["result"]
        link = c["link"]
        weight = c["weight"]
        if ok:
            status = Text("CUMPLE", style="bold bright_green")
            ref = Text.from_markup(f"[link={link}]{link}[/link]", style="underline bright_cyan")
        else:
            status = Text("REVISAR", style="bold bright_red")
            ref = Text.from_markup(f"[link={link}]{link}[/link]", style="underline bright_cyan")
        table.add_row(label, status, detail, str(weight), ref)

    return table


def build_reference_panel(checks):
    """Lista todos los enlaces OWASP en texto plano para que no se pierdan
    aunque el terminal no renderice hipervínculos."""
    body = Text()
    body.append("Guía de referencia utilizada:\n", style="bold")
    body.append("OWASP Cheat Sheet Series\n", style="bold cyan")
    body.append("Enlaces directos a los artículos OWASP por cabecera:\n", style="bold")
    seen = set()
    for c in checks:
        link = c["link"]
        if link in seen:
            continue
        seen.add(link)
        body.append(f"  • {c['label']}:\n", style="bold")
        body.append(f"    {link}\n", style="underline bright_cyan")
    return Panel(body, border_style="blue", box=box.ROUNDED)


def render_report(hostname, data, console):
    scan = data.get("scan", {})
    response_headers = scan.get("responseHeaders", {})
    formal_checks, extra_checks = collect_checks(data.get("tests", {}), response_headers)
    all_checks = formal_checks + extra_checks
    owasp_score, _ = compute_owasp_score(all_checks)
    grade = owasp_grade(owasp_score)

    console.rule(f"[bold blue]Auditoría de cabeceras de seguridad HTTP — {hostname}[/bold blue]")
    console.print(build_summary_panel(hostname, scan, owasp_score, grade))
    console.print()
    if response_headers:
        console.print(build_headers_table(response_headers))
        console.print()
    if formal_checks:
        console.print(build_tests_table(formal_checks))
        console.print()
    if extra_checks:
        console.print(build_extra_checks_table(extra_checks))
        console.print()
    console.print(build_reference_panel(all_checks))

    return all_checks, owasp_score, grade


def build_pdf(hostname, scan, response_headers, formal_checks, extra_checks,
              owasp_score, owasp_grade, out_path):
    """Genera un informe PDF con reportlab. Los enlaces OWASP se incluyen
    como hipervínculos clicables y como texto visible."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
        from xml.sax.saxutils import escape
    except ImportError:
        Console(stderr=True).print(
            "[bold red]Error:[/bold red] para exportar a PDF se requiere 'reportlab'.\n"
            "Instálalo con: [cyan]pip install reportlab[/cyan]"
        )
        sys.exit(1)

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=8, spaceAfter=4)
    body = styles["BodyText"]
    cell = ParagraphStyle("Cell", parent=body, fontSize=8, leading=10)
    cell_bold = ParagraphStyle("CellBold", parent=cell, fontName="Helvetica-Bold")

    def p(text, style=body):
        return Paragraph(text, style)

    def link_para(url):
        return Paragraph(f'<a href="{url}" color="blue">{url}</a>', cell)

    def make_table(header, rows, col_widths):
        data = [header] + rows
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef3f8")]),
        ]))
        return t

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        rightMargin=15 * mm, leftMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
    )
    story = []
    story.append(p(f"Auditoría de cabeceras de seguridad HTTP — {hostname}", title_style))
    story.append(Spacer(1, 4 * mm))

    obs_grade = scan.get("grade", "N/A")
    obs_score = scan.get("score", 0)
    story.append(p(
        f"<b>Nota OWASP:</b> {owasp_grade} &nbsp;&nbsp; "
        f"<b>Puntaje OWASP:</b> {owasp_score}/100"
    ))
    story.append(p(
        f"<b>Puntaje Observatory (referencia):</b> {obs_score}/100 ({obs_grade})"
    ))
    story.append(p(f"<b>Estado HTTP:</b> {scan.get('statusCode', 'N/A')}"))
    passed = scan.get("testsPassed", 0)
    failed = scan.get("testsFailed", 0)
    story.append(p(f"<b>Pruebas:</b> {passed} aprobadas / {failed} fallidas"))
    story.append(Spacer(1, 4 * mm))

    if response_headers:
        story.append(p("Cabeceras HTTP recibidas", h2))
        rows = [[Paragraph(k, cell_bold), Paragraph(str(v), cell)]
                for k, v in sorted(response_headers.items())]
        story.append(make_table(
            [Paragraph("Cabecera", cell_bold), Paragraph("Valor", cell_bold)],
            rows, [60 * mm, 120 * mm],
        ))
        story.append(Spacer(1, 4 * mm))

    if formal_checks:
        story.append(p("Evaluación de cabeceras de seguridad (OWASP Cheat Sheet Series)", h2))
        rows = []
        for c in formal_checks:
            estado = "CUMPLE" if c["passed"] is True else ("NO CUMPLE" if c["passed"] is False else "N/A")
            color = colors.green if c["passed"] is True else (colors.red if c["passed"] is False else colors.grey)
            rec = Paragraph(
                f"{escape(c['recommendation'])}<br/><a href=\"{c['link']}\" color=\"blue\">{c['link']}</a>",
                cell,
            )
            rows.append([
                Paragraph(c["label"], cell_bold),
                Paragraph(f'<font color="{color.hexval()}"><b>{estado}</b></font>', cell),
                Paragraph(escape(str(c["result"])), cell),
                Paragraph(f"{c['modifier']:+d}" if c["modifier"] else "0", cell),
                Paragraph(str(c["weight"]), cell),
                rec,
            ])
        story.append(make_table(
            [Paragraph(h, cell_bold) for h in
             ("Cabecera / Control", "Estado", "Resultado", "Impacto", "Peso OWASP", "Recomendación OWASP")],
            rows, [38 * mm, 18 * mm, 30 * mm, 14 * mm, 14 * mm, 56 * mm],
        ))
        story.append(Spacer(1, 4 * mm))

    if extra_checks:
        story.append(p("Cabeceras adicionales según OWASP (no puntuadas por mdn-http-observatory)", h2))
        rows = []
        for c in extra_checks:
            estado = "CUMPLE" if c["passed"] is True else "REVISAR"
            color = colors.green if c["passed"] is True else colors.red
            rows.append([
                Paragraph(c["label"], cell_bold),
                Paragraph(f'<font color="{color.hexval()}"><b>{estado}</b></font>', cell),
                Paragraph(escape(str(c["result"])), cell),
                Paragraph(str(c["weight"]), cell),
                link_para(c["link"]),
            ])
        story.append(make_table(
            [Paragraph(h, cell_bold) for h in
             ("Cabecera / Control", "Estado", "Detalle", "Peso OWASP", "Referencia OWASP")],
            rows, [40 * mm, 18 * mm, 52 * mm, 16 * mm, 44 * mm],
        ))
        story.append(Spacer(1, 4 * mm))

    story.append(p("Referencias OWASP (enlaces directos)", h2))
    seen = set()
    for c in formal_checks + extra_checks:
        link = c["link"]
        if link in seen:
            continue
        seen.add(link)
        story.append(Paragraph(
            f"<b>{c['label']}:</b> <a href=\"{link}\" color=\"blue\">{link}</a>",
            body,
        ))

    doc.build(story)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audita las cabeceras de seguridad HTTP de un dominio usando "
                     "mdn-http-observatory-scan y las evalúa según el OWASP Cheat Sheet Series."
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
    parser.add_argument(
        "--pdf-out",
        help="Ruta donde exportar el informe en formato PDF (requiere 'reportlab')",
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

    scan = data.get("scan", {})
    response_headers = scan.get("responseHeaders", {})
    formal_checks, extra_checks = collect_checks(data.get("tests", {}), response_headers)
    all_checks = formal_checks + extra_checks
    owasp_score, _ = compute_owasp_score(all_checks)
    grade = owasp_grade(owasp_score)

    render_report(args.dominio, data, console)

    if args.pdf_out:
        build_pdf(
            args.dominio, scan, response_headers,
            formal_checks, extra_checks,
            owasp_score, grade, args.pdf_out,
        )
        console.print(f"[green]Informe PDF guardado en:[/green] {args.pdf_out}")


if __name__ == "__main__":
    main()
