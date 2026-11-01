"""Pure functions that evaluate HTTP response headers. No network access here."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping


@dataclass(frozen=True)
class Finding:
    name: str
    status: str  # "pass", "warn", or "fail"
    detail: str


@dataclass
class Report:
    url: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        points = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
        if not self.findings:
            return 0
        total = sum(points[f.status] for f in self.findings)
        return round(100 * total / len(self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if s >= threshold:
                return letter
        return "F"


Headers = dict[str, str]


def check_hsts(h: Headers) -> Finding:
    value = h.get("strict-transport-security")
    if value is None:
        return Finding("Strict-Transport-Security", "fail", "Header missing")
    if "max-age=" not in value.lower():
        return Finding("Strict-Transport-Security", "fail", "No max-age directive")
    return Finding("Strict-Transport-Security", "pass", value)


def check_csp(h: Headers) -> Finding:
    value = h.get("content-security-policy")
    if value is None:
        return Finding("Content-Security-Policy", "fail", "Header missing")
    if "unsafe-inline" in value or "unsafe-eval" in value:
        return Finding("Content-Security-Policy", "warn", "Contains unsafe-inline or unsafe-eval")
    return Finding("Content-Security-Policy", "pass", value)


def check_frame_options(h: Headers) -> Finding:
    value = h.get("x-frame-options")
    csp = h.get("content-security-policy", "")
    if value is None and "frame-ancestors" not in csp:
        return Finding("X-Frame-Options", "fail", "Neither X-Frame-Options nor frame-ancestors set")
    return Finding("X-Frame-Options", "pass", value or "frame-ancestors set in CSP")


def check_content_type_options(h: Headers) -> Finding:
    if h.get("x-content-type-options", "").lower() == "nosniff":
        return Finding("X-Content-Type-Options", "pass", "nosniff")
    return Finding("X-Content-Type-Options", "fail", "Missing or not set to nosniff")


def check_referrer_policy(h: Headers) -> Finding:
    value = h.get("referrer-policy")
    if value is None:
        return Finding("Referrer-Policy", "warn", "Header missing")
    if value.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        return Finding("Referrer-Policy", "fail", f"Weak policy: {value}")
    return Finding("Referrer-Policy", "pass", value)


def check_server_disclosure(h: Headers) -> Finding:
    value = h.get("server")
    if value is None:
        return Finding("Server header", "pass", "Not disclosed")
    if any(ch.isdigit() for ch in value):
        return Finding("Server header", "warn", f"Reveals version: {value}")
    return Finding("Server header", "pass", f"Present without version: {value}")


ALL_CHECKS: tuple[Callable[[Headers], Finding], ...] = (
    check_hsts,
    check_csp,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_server_disclosure,
)


def evaluate(url: str, headers: Mapping[str, str]) -> Report:
    lowered: Headers = {k.lower(): v for k, v in headers.items()}
    report = Report(url=url)
    for check in ALL_CHECKS:
        report.findings.append(check(lowered))
    return report
