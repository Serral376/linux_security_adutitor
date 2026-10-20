#!/usr/bin/env python3
"""
Linux Security Auditor
Средней сложности инструмент аудита безопасности Linux для портфолио.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from auditor.core import Auditor
from auditor.report import save_reports
from auditor.utils import Severity
from auditor.checks import AVAILABLE_CHECKS

console = Console()


def print_banner():
    banner = r"""
[bold blue]╔══════════════════════════════════════════════════╗
║         Linux Security Auditor  v1.0             ║
║     Portfolio project for InfoSec specialists    ║
╚══════════════════════════════════════════════════╝[/]
"""
    console.print(banner)


def print_summary(auditor: Auditor):
    summary = auditor.summary()
    counts = summary["counts"]

    table = Table(title="Результаты аудита", box=box.ROUNDED, show_header=True)
    table.add_column("Уровень", style="bold")
    table.add_column("Количество", justify="right")

    color_map = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
        "pass": "green",
    }

    for sev in ["critical", "high", "medium", "low", "info", "pass"]:
        cnt = counts.get(sev, 0)
        if cnt > 0:
            table.add_row(f"[{color_map[sev]}]{sev.upper()}[/]", str(cnt))

    console.print(table)
    console.print()
    console.print(f"[bold]Всего проблем (C+H+M+L):[/] {summary['total_issues']}")
    console.print(f"[bold]Время выполнения:[/] {summary['duration']} сек")
    console.print(f"[bold]Права root:[/] {'Да' if summary['is_root'] else 'Нет (некоторые проверки ограничены)'}")
    console.print()


def print_findings(auditor: Auditor, verbose: bool = False):
    findings = auditor.get_all_findings()
    if not findings:
        console.print("[green]Критических и значимых проблем не обнаружено.[/]")
        return

    for f in sorted(findings, key=lambda x: -x.severity.weight):
        color = f.severity.color
        title = f"[{color}]{f.severity.value.upper()}[/{color}] [{f.check_id}] {f.title}"
        body = f"{f.description}"
        if f.remediation:
            body += f"\n[bold]Рекомендация:[/] {f.remediation}"
        if verbose and f.evidence:
            body += f"\n[dim]{f.evidence[:300]}[/]"
        console.print(Panel(body, title=title, border_style=color, expand=False))


def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Auditor — аудит безопасности Linux-системы",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python main.py
  python main.py --only users,ssh,firewall
  python main.py --verbose --no-report
  sudo python main.py
        """,
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Путь к конфигурационному файлу (default: config.yaml)",
    )
    parser.add_argument(
        "--only",
        help="Запустить только указанные проверки (через запятую). Доступно: "
        + ", ".join(AVAILABLE_CHECKS.keys()),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Показывать доказательства (evidence)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Не сохранять отчёты на диск",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="Показать список доступных проверок и выйти",
    )

    args = parser.parse_args()

    if args.list_checks:
        console.print("[bold]Доступные проверки:[/]")
        for name in AVAILABLE_CHECKS:
            console.print(f"  • {name}")
        sys.exit(0)

    print_banner()

    only = None
    if args.only:
        only = [x.strip() for x in args.only.split(",") if x.strip()]
        unknown = set(only) - set(AVAILABLE_CHECKS.keys())
        if unknown:
            console.print(f"[red]Неизвестные проверки: {', '.join(unknown)}[/]")
            sys.exit(1)

    console.print("[bold]Запуск аудита...[/]\n")

    auditor = Auditor(config_path=args.config)
    auditor.run(only=only)

    print_summary(auditor)
    print_findings(auditor, verbose=args.verbose)

    if not args.no_report:
        saved = save_reports(auditor)
        console.print("[bold green]Отчёты сохранены:[/]")
        for p in saved:
            console.print(f"  → {p}")

    # Exit code based on findings
    summary = auditor.summary()
    if summary["counts"]["critical"] > 0:
        sys.exit(2)
    if summary["counts"]["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
