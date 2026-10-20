"""Cron and scheduled tasks checks."""

from __future__ import annotations

import os
from typing import List

from auditor.utils import Finding, Severity, run_command, read_file, file_exists


def check_cron() -> List[Finding]:
    findings: List[Finding] = []

    # System crontab
    cron_files = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ]

    suspicious_entries = []

    # /etc/crontab
    if file_exists("/etc/crontab"):
        content = read_file("/etc/crontab") or ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Look for weird things
            if any(x in line.lower() for x in ("curl ", "wget ", "nc ", "ncat ", "python -c", "bash -i", "/dev/tcp")):
                suspicious_entries.append(f"/etc/crontab: {line}")

    # /etc/cron.d/*
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        for fname in os.listdir(cron_d):
            path = os.path.join(cron_d, fname)
            if os.path.isfile(path):
                content = read_file(path) or ""
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if any(x in line.lower() for x in ("curl ", "wget ", "nc ", "python -c", "bash -i")):
                        suspicious_entries.append(f"{path}: {line}")

    if suspicious_entries:
        findings.append(Finding(
            check_id="CRON-001",
            title="Подозрительные записи в cron",
            severity=Severity.HIGH,
            description="Обнаружены потенциально вредоносные команды в планировщике.",
            evidence="\n".join(suspicious_entries[:10]),
            remediation="Проверьте и удалите подозрительные задачи.",
            category="cron",
        ))
    else:
        findings.append(Finding(
            check_id="CRON-001",
            title="Подозрительных записей в cron не найдено",
            severity=Severity.PASS,
            description="Базовый поиск вредоносных паттернов в cron прошёл успешно.",
            category="cron",
        ))

    # World-writable cron directories
    for path in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron"]:
        if os.path.isdir(path):
            st = os.stat(path)
            mode = st.st_mode
            if mode & 0o002:  # world writable
                findings.append(Finding(
                    check_id="CRON-002",
                    title=f"World-writable директория cron: {path}",
                    severity=Severity.CRITICAL,
                    description="Любой пользователь может добавлять задачи.",
                    remediation=f"chmod 755 {path}",
                    category="cron",
                ))

    # List current user crontab (info)
    rc, out, _ = run_command(["crontab", "-l"])
    if rc == 0 and out.strip():
        findings.append(Finding(
            check_id="CRON-INFO",
            title="Crontab текущего пользователя",
            severity=Severity.INFO,
            description="Задачи текущего пользователя.",
            evidence=out[:800],
            category="cron",
        ))

    return findings
