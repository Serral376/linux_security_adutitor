"""Package and update related checks."""

from __future__ import annotations

from typing import List

from auditor.utils import Finding, Severity, run_command, which


def check_packages() -> List[Finding]:
    findings: List[Finding] = []

    # Detect package manager
    if which("apt"):
        return _check_apt(findings)
    elif which("dnf") or which("yum"):
        return _check_rpm(findings)
    elif which("pacman"):
        return _check_pacman(findings)
    else:
        findings.append(Finding(
            check_id="PKG-000",
            title="Менеджер пакетов не определён",
            severity=Severity.INFO,
            description="Не удалось определить apt/dnf/yum/pacman.",
            category="packages",
        ))
        return findings


def _check_apt(findings: List[Finding]) -> List[Finding]:
    # Upgradable packages
    rc, out, err = run_command(["apt", "list", "--upgradable"], timeout=30)
    if rc == 0 and out:
        lines = [l for l in out.splitlines() if "/" in l and "upgradable" in l.lower()]
        count = len(lines)
        if count > 0:
            severity = Severity.HIGH if count > 20 else Severity.MEDIUM if count > 5 else Severity.LOW
            findings.append(Finding(
                check_id="PKG-001",
                title=f"Доступно обновлений: {count}",
                severity=severity,
                description="Система имеет неустановленные обновления безопасности/пакетов.",
                evidence="\n".join(lines[:25]),
                remediation="Выполните: sudo apt update && sudo apt upgrade",
                category="packages",
            ))
        else:
            findings.append(Finding(
                check_id="PKG-001",
                title="Система актуальна (apt)",
                severity=Severity.PASS,
                description="Нет доступных обновлений.",
                category="packages",
            ))
    else:
        # try without list (some systems need apt update first)
        findings.append(Finding(
            check_id="PKG-001i",
            title="Не удалось проверить обновления apt",
            severity=Severity.INFO,
            description=err or "Возможно, требуется 'apt update' или права.",
            category="packages",
        ))

    # Check if unattended-upgrades is installed
    rc, out, _ = run_command(["dpkg", "-l", "unattended-upgrades"])
    if rc != 0:
        findings.append(Finding(
            check_id="PKG-002",
            title="unattended-upgrades не установлен",
            severity=Severity.LOW,
            description="Автоматические обновления безопасности не настроены.",
            remediation="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
            category="packages",
        ))

    return findings


def _check_rpm(findings: List[Finding]) -> List[Finding]:
    cmd = "dnf" if which("dnf") else "yum"
    rc, out, _ = run_command([cmd, "check-update"], timeout=40)
    # dnf/yum return 100 when updates are available
    if rc in (0, 100) and out:
        lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Last metadata")]
        count = len([l for l in lines if "." in l])
        if count > 0:
            severity = Severity.HIGH if count > 20 else Severity.MEDIUM
            findings.append(Finding(
                check_id="PKG-001",
                title=f"Доступно обновлений: ~{count}",
                severity=severity,
                description=f"Найдены обновления через {cmd}.",
                evidence="\n".join(lines[:20]),
                remediation=f"sudo {cmd} update",
                category="packages",
            ))
        else:
            findings.append(Finding(
                check_id="PKG-001",
                title="Система актуальна",
                severity=Severity.PASS,
                description="Нет доступных обновлений.",
                category="packages",
            ))
    return findings


def _check_pacman(findings: List[Finding]) -> List[Finding]:
    rc, out, _ = run_command(["pacman", "-Qu"], timeout=20)
    if rc == 0 and out:
        lines = out.splitlines()
        count = len(lines)
        severity = Severity.HIGH if count > 15 else Severity.MEDIUM
        findings.append(Finding(
            check_id="PKG-001",
            title=f"Доступно обновлений: {count}",
            severity=severity,
            description="Система Arch/Manjaro имеет обновления.",
            evidence="\n".join(lines[:20]),
            remediation="sudo pacman -Syu",
            category="packages",
        ))
    else:
        findings.append(Finding(
            check_id="PKG-001",
            title="Система актуальна (pacman)",
            severity=Severity.PASS,
            description="Нет доступных обновлений.",
            category="packages",
        ))
    return findings
