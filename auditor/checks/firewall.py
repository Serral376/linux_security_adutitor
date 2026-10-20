"""Firewall status checks."""

from __future__ import annotations

from typing import List

from auditor.utils import Finding, Severity, run_command, which


def check_firewall() -> List[Finding]:
    findings: List[Finding] = []

    # Check ufw
    if which("ufw"):
        rc, out, _ = run_command(["ufw", "status"], timeout=10)
        if rc == 0:
            if "Status: active" in out:
                findings.append(Finding(
                    check_id="FW-001",
                    title="UFW активен",
                    severity=Severity.PASS,
                    description="Uncomplicated Firewall включён.",
                    evidence=out[:800],
                    category="firewall",
                ))
            else:
                findings.append(Finding(
                    check_id="FW-001",
                    title="UFW установлен, но не активен",
                    severity=Severity.HIGH,
                    description="Firewall ufw присутствует, но выключен.",
                    evidence=out,
                    remediation="sudo ufw enable",
                    category="firewall",
                ))
        return findings

    # Check firewalld
    if which("firewall-cmd"):
        rc, out, _ = run_command(["firewall-cmd", "--state"], timeout=10)
        if rc == 0 and "running" in out.lower():
            findings.append(Finding(
                check_id="FW-001",
                title="firewalld активен",
                severity=Severity.PASS,
                description="firewalld запущен.",
                category="firewall",
            ))
        else:
            findings.append(Finding(
                check_id="FW-001",
                title="firewalld не активен",
                severity=Severity.HIGH,
                description="firewalld установлен, но не работает.",
                remediation="sudo systemctl enable --now firewalld",
                category="firewall",
            ))
        return findings

    # Check iptables / nftables presence
    has_iptables = which("iptables")
    has_nft = which("nft")

    if has_iptables:
        rc, out, _ = run_command(["iptables", "-L", "-n"], timeout=10)
        if rc == 0:
            # Very rough check: if only default ACCEPT policies and few rules
            policy_accept = out.count("policy ACCEPT")
            if policy_accept >= 3 and "Chain INPUT" in out:
                # count non-header lines roughly
                rule_lines = [l for l in out.splitlines() if l and not l.startswith("Chain") and not l.startswith("target")]
                if len(rule_lines) < 5:
                    findings.append(Finding(
                        check_id="FW-002",
                        title="iptables почти пустой (всё разрешено)",
                        severity=Severity.HIGH,
                        description="Похоже, нет значимых правил фильтрации.",
                        evidence=out[:600],
                        remediation="Настройте правила iptables/nftables или установите ufw/firewalld.",
                        category="firewall",
                    ))
                else:
                    findings.append(Finding(
                        check_id="FW-002",
                        title="iptables имеет правила",
                        severity=Severity.INFO,
                        description="Обнаружены правила iptables.",
                        evidence=out[:600],
                        category="firewall",
                    ))
    elif has_nft:
        rc, out, _ = run_command(["nft", "list", "ruleset"], timeout=10)
        if rc == 0 and out.strip():
            findings.append(Finding(
                check_id="FW-003",
                title="nftables настроен",
                severity=Severity.INFO,
                description="Обнаружены правила nftables.",
                category="firewall",
            ))
        else:
            findings.append(Finding(
                check_id="FW-003",
                title="nftables пустой или недоступен",
                severity=Severity.MEDIUM,
                description="Нет видимых правил nftables.",
                category="firewall",
            ))
    else:
        findings.append(Finding(
            check_id="FW-000",
            title="Firewall не обнаружен",
            severity=Severity.HIGH,
            description="Не найдены ufw, firewalld, iptables или nft.",
            remediation="Установите и настройте ufw (Ubuntu/Debian) или firewalld (RHEL).",
            category="firewall",
        ))

    return findings
