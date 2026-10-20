"""SSH configuration security checks."""

from __future__ import annotations

import os
import re
from typing import List, Dict

from auditor.utils import Finding, Severity, read_file, file_exists, get_file_permissions, get_owner


SSH_CONFIG_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
]


def _parse_sshd_config(content: str) -> Dict[str, str]:
    """Parse simple key-value from sshd_config (last value wins)."""
    config: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle "Key Value" and "Key=Value"
        if "=" in line:
            key, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1]
        config[key.strip().lower()] = value.strip()
    return config


def check_ssh() -> List[Finding]:
    findings: List[Finding] = []

    main_config = "/etc/ssh/sshd_config"
    if not file_exists(main_config):
        findings.append(Finding(
            check_id="SSH-000",
            title="sshd_config не найден",
            severity=Severity.INFO,
            description="Файл /etc/ssh/sshd_config отсутствует. Возможно, SSH-сервер не установлен.",
            category="ssh",
        ))
        return findings

    content = read_file(main_config) or ""
    # Also include drop-in configs
    drop_in_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(drop_in_dir):
        for fname in sorted(os.listdir(drop_in_dir)):
            if fname.endswith(".conf"):
                extra = read_file(os.path.join(drop_in_dir, fname))
                if extra:
                    content += "\n" + extra

    cfg = _parse_sshd_config(content)

    # 1. PermitRootLogin
    permit_root = cfg.get("permitrootlogin", "prohibit-password").lower()
    if permit_root in ("yes", "without-password"):
        findings.append(Finding(
            check_id="SSH-001",
            title="Разрешён вход root по SSH",
            severity=Severity.HIGH if permit_root == "yes" else Severity.MEDIUM,
            description=f"PermitRootLogin = {permit_root}",
            evidence=f"PermitRootLogin {permit_root}",
            remediation="Установите 'PermitRootLogin no' или 'prohibit-password' и используйте sudo.",
            category="ssh",
        ))
    else:
        findings.append(Finding(
            check_id="SSH-001",
            title="Вход root по SSH ограничен",
            severity=Severity.PASS,
            description=f"PermitRootLogin = {permit_root}",
            category="ssh",
        ))

    # 2. PasswordAuthentication
    pass_auth = cfg.get("passwordauthentication", "yes").lower()
    if pass_auth == "yes":
        findings.append(Finding(
            check_id="SSH-002",
            title="Разрешена аутентификация по паролю",
            severity=Severity.MEDIUM,
            description="PasswordAuthentication yes — рекомендуется только ключи.",
            evidence="PasswordAuthentication yes",
            remediation="Установите 'PasswordAuthentication no' и используйте SSH-ключи.",
            category="ssh",
        ))
    else:
        findings.append(Finding(
            check_id="SSH-002",
            title="Аутентификация по паролю отключена",
            severity=Severity.PASS,
            description="PasswordAuthentication no",
            category="ssh",
        ))

    # 3. Protocol
    protocol = cfg.get("protocol", "2")
    if protocol != "2":
        findings.append(Finding(
            check_id="SSH-003",
            title="Используется устаревший протокол SSH",
            severity=Severity.CRITICAL,
            description=f"Protocol = {protocol}",
            remediation="Установите Protocol 2.",
            category="ssh",
        ))

    # 4. PermitEmptyPasswords
    empty = cfg.get("permitemptypasswords", "no").lower()
    if empty == "yes":
        findings.append(Finding(
            check_id="SSH-004",
            title="Разрешены пустые пароли",
            severity=Severity.CRITICAL,
            description="PermitEmptyPasswords yes",
            remediation="Установите PermitEmptyPasswords no.",
            category="ssh",
        ))

    # 5. X11Forwarding
    x11 = cfg.get("x11forwarding", "no").lower()
    if x11 == "yes":
        findings.append(Finding(
            check_id="SSH-005",
            title="Включён X11 Forwarding",
            severity=Severity.LOW,
            description="X11Forwarding yes может увеличивать поверхность атаки.",
            remediation="Отключите X11Forwarding, если не требуется.",
            category="ssh",
        ))

    # 6. MaxAuthTries
    max_tries = cfg.get("maxauthtries", "6")
    try:
        if int(max_tries) > 4:
            findings.append(Finding(
                check_id="SSH-006",
                title="Слишком много попыток аутентификации",
                severity=Severity.LOW,
                description=f"MaxAuthTries = {max_tries}",
                remediation="Рекомендуется MaxAuthTries 3 или 4.",
                category="ssh",
            ))
    except ValueError:
        pass

    # 7. Permissions on sshd_config
    perms = get_file_permissions(main_config)
    owner, group = get_owner(main_config)
    if perms and perms != "600" and perms != "644":
        findings.append(Finding(
            check_id="SSH-007",
            title="Небезопасные права на sshd_config",
            severity=Severity.MEDIUM,
            description=f"Права {perms}, владелец {owner}:{group}",
            evidence=f"{main_config} → {perms}",
            remediation="chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
            category="ssh",
        ))

    # 8. Host keys permissions
    for key_file in ["/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key",
                     "/etc/ssh/ssh_host_ecdsa_key"]:
        if file_exists(key_file):
            perms = get_file_permissions(key_file)
            if perms and perms != "600":
                findings.append(Finding(
                    check_id="SSH-008",
                    title=f"Небезопасные права на приватный ключ",
                    severity=Severity.HIGH,
                    description=f"{key_file} имеет права {perms}",
                    remediation=f"chmod 600 {key_file}",
                    category="ssh",
                ))

    return findings
