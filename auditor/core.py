"""Core orchestrator of Linux Security Auditor."""

from __future__ import annotations

import time
from typing import List, Dict, Any
from pathlib import Path

import yaml

from auditor.utils import CheckResult, Finding, Severity, current_timestamp, is_root
from auditor.checks import AVAILABLE_CHECKS


class Auditor:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.results: List[CheckResult] = []
        self.start_time = None
        self.end_time = None

    def _load_config(self, path: str) -> dict:
        default = {
            "min_severity": "info",
            "checks": {name: True for name in AVAILABLE_CHECKS},
            "report": {
                "output_dir": "reports",
                "formats": ["markdown", "html"],
                "include_passed": False,
            },
        }
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
            # shallow merge
            default.update(user_cfg)
            if "checks" in user_cfg:
                default["checks"].update(user_cfg["checks"])
            if "report" in user_cfg:
                default["report"].update(user_cfg["report"])
            return default
        except FileNotFoundError:
            return default

    def run(self, only: List[str] | None = None) -> List[CheckResult]:
        self.start_time = time.time()
        enabled = self.config.get("checks", {})

        for name, func in AVAILABLE_CHECKS.items():
            if only and name not in only:
                continue
            if not enabled.get(name, True):
                continue

            start = time.time()
            try:
                findings = func()
                result = CheckResult(name=name, findings=findings, duration=time.time() - start)
            except Exception as e:
                result = CheckResult(
                    name=name,
                    findings=[],
                    duration=time.time() - start,
                    error=str(e),
                )
            self.results.append(result)

        self.end_time = time.time()
        return self.results

    def get_all_findings(self, include_passed: bool | None = None) -> List[Finding]:
        if include_passed is None:
            include_passed = self.config.get("report", {}).get("include_passed", False)

        min_sev = self.config.get("min_severity", "info")
        min_weight = Severity(min_sev).weight if min_sev != "pass" else 0

        all_findings = []
        for res in self.results:
            for f in res.findings:
                if f.severity == Severity.PASS and not include_passed:
                    continue
                if f.severity.weight < min_weight:
                    continue
                all_findings.append(f)
        return all_findings

    def summary(self) -> Dict[str, Any]:
        findings = self.get_all_findings(include_passed=True)
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1

        return {
            "timestamp": current_timestamp(),
            "duration": round((self.end_time or time.time()) - (self.start_time or time.time()), 2),
            "is_root": is_root(),
            "checks_run": len(self.results),
            "counts": counts,
            "total_issues": counts["critical"] + counts["high"] + counts["medium"] + counts["low"],
        }
