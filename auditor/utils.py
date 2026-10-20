"""Utility functions for Linux Security Auditor."""

from __future__ import annotations

import os
import pwd
import grp
import subprocess
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Any
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def color(self) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan",
            "pass": "green",
        }.get(self.value, "white")

    @property
    def weight(self) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
            "pass": 0,
        }.get(self.value, 0)


@dataclass
class Finding:
    """Single security finding."""
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    category: str = "general"

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class CheckResult:
    """Result of one check module."""
    name: str
    findings: List[Finding] = field(default_factory=list)
    duration: float = 0.0
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


def run_command(cmd: List[str] | str, timeout: int = 15) -> tuple[int, str, str]:
    """Run shell command and return (returncode, stdout, stderr)."""
    try:
        if isinstance(cmd, str):
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def is_root() -> bool:
    return os.geteuid() == 0


def file_exists(path: str) -> bool:
    return os.path.exists(path)


def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def get_file_permissions(path: str) -> Optional[str]:
    try:
        st = os.stat(path)
        mode = st.st_mode
        return oct(mode)[-3:]
    except Exception:
        return None


def get_owner(path: str) -> tuple[str, str]:
    try:
        st = os.stat(path)
        uid = st.st_uid
        gid = st.st_gid
        user = pwd.getpwuid(uid).pw_name
        group = grp.getgrgid(gid).gr_name
        return user, group
    except Exception:
        return "?", "?"


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
