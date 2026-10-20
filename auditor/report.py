"""Report generation (Markdown + HTML)."""

from __future__ import annotations

import os
from datetime import datetime
from typing import List
from pathlib import Path

from auditor.utils import Finding, Severity, CheckResult
from auditor.core import Auditor


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.PASS,
]


def generate_markdown(auditor: Auditor, output_path: str) -> str:
    summary = auditor.summary()
    findings = auditor.get_all_findings()

    lines = []
    lines.append("# Linux Security Audit Report")
    lines.append("")
    lines.append(f"**Дата:** {summary['timestamp']}  ")
    lines.append(f"**Длительность:** {summary['duration']} сек  ")
    lines.append(f"**Запущено от root:** {'Да' if summary['is_root'] else 'Нет'}  ")
    lines.append(f"**Проверок выполнено:** {summary['checks_run']}  ")
    lines.append("")
    lines.append("## Сводка")
    lines.append("")
    lines.append("| Уровень | Количество |")
    lines.append("|---------|------------|")
    for sev in SEVERITY_ORDER:
        cnt = summary["counts"].get(sev.value, 0)
        if cnt > 0 or sev.value in ("critical", "high", "medium"):
            lines.append(f"| {sev.value.upper()} | {cnt} |")
    lines.append("")
    lines.append(f"**Всего проблем (Critical+High+Medium+Low):** {summary['total_issues']}")
    lines.append("")

    # Group by severity
    by_sev: dict[str, List[Finding]] = {s.value: [] for s in SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity.value].append(f)

    for sev in SEVERITY_ORDER:
        items = by_sev[sev.value]
        if not items:
            continue
        lines.append(f"## {sev.value.upper()} ({len(items)})")
        lines.append("")
        for f in items:
            lines.append(f"### [{f.check_id}] {f.title}")
            lines.append("")
            lines.append(f"- **Категория:** {f.category}")
            lines.append(f"- **Описание:** {f.description}")
            if f.evidence:
                lines.append(f"- **Доказательство:**")
                lines.append("```")
                lines.append(f.evidence[:1000])
                lines.append("```")
            if f.remediation:
                lines.append(f"- **Рекомендация:** {f.remediation}")
            lines.append("")

    # Errors
    errors = [r for r in auditor.results if r.error]
    if errors:
        lines.append("## Ошибки выполнения")
        lines.append("")
        for r in errors:
            lines.append(f"- **{r.name}**: {r.error}")
        lines.append("")

    lines.append("---")
    lines.append("*Сгенерировано Linux Security Auditor*")

    content = "\n".join(lines)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path


def generate_html(auditor: Auditor, output_path: str) -> str:
    summary = auditor.summary()
    findings = auditor.get_all_findings()

    color_map = {
        "critical": "#d32f2f",
        "high": "#f44336",
        "medium": "#ff9800",
        "low": "#2196f3",
        "info": "#00bcd4",
        "pass": "#4caf50",
    }

    rows = []
    for f in sorted(findings, key=lambda x: -x.severity.weight):
        color = color_map.get(f.severity.value, "#666")
        evidence_html = f"<pre>{_escape(f.evidence[:800])}</pre>" if f.evidence else ""
        rem = f"<p><strong>Рекомендация:</strong> {_escape(f.remediation)}</p>" if f.remediation else ""
        rows.append(f"""
        <div class="finding" style="border-left: 5px solid {color};">
            <h3><span class="badge" style="background:{color}">{f.severity.value.upper()}</span>
            [{_escape(f.check_id)}] {_escape(f.title)}</h3>
            <p><em>Категория: {_escape(f.category)}</em></p>
            <p>{_escape(f.description)}</p>
            {evidence_html}
            {rem}
        </div>
        """)

    counts_html = "".join(
        f'<div class="stat"><span class="num" style="color:{color_map.get(k, "#333")}">{v}</span><span class="label">{k}</span></div>'
        for k, v in summary["counts"].items() if v > 0
    )

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Linux Security Audit Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; color: #222; }}
h1 {{ color: #1a237e; }}
.summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 24px 0; }}
.stat {{ background: white; padding: 16px 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align: center; min-width: 90px; }}
.stat .num {{ display: block; font-size: 28px; font-weight: 700; }}
.stat .label {{ font-size: 12px; text-transform: uppercase; color: #666; }}
.finding {{ background: white; margin: 16px 0; padding: 16px 20px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
.badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 8px; }}
pre {{ background: #f0f0f0; padding: 10px; overflow-x: auto; font-size: 13px; border-radius: 4px; }}
.meta {{ color: #666; font-size: 14px; }}
footer {{ margin-top: 40px; color: #999; font-size: 13px; }}
</style>
</head>
<body>
<h1>Linux Security Audit Report</h1>
<p class="meta">
Дата: {summary['timestamp']}<br>
Длительность: {summary['duration']} сек<br>
Root: {'Да' if summary['is_root'] else 'Нет'}<br>
Проверок: {summary['checks_run']}<br>
Всего проблем: <strong>{summary['total_issues']}</strong>
</p>

<div class="summary">
{counts_html}
</div>

{''.join(rows)}

<footer>Сгенерировано Linux Security Auditor</footer>
</body>
</html>
"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def save_reports(auditor: Auditor) -> List[str]:
    report_cfg = auditor.config.get("report", {})
    out_dir = report_cfg.get("output_dir", "reports")
    formats = report_cfg.get("formats", ["markdown", "html"])
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []

    if "markdown" in formats:
        path = os.path.join(out_dir, f"audit_{ts}.md")
        generate_markdown(auditor, path)
        saved.append(path)
    if "html" in formats:
        path = os.path.join(out_dir, f"audit_{ts}.html")
        generate_html(auditor, path)
        saved.append(path)
    return saved
