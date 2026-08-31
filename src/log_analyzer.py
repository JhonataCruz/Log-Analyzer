#!/usr/bin/env python3
"""Small log analyzer for SSH and web server logs."""

from __future__ import annotations

import argparse
import html
import re
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


SSH_FAILURE_RE = re.compile(
    r"(?:Failed password for (?:(?:invalid )?user |)|Invalid user )(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
SSH_ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^]]+)\] "(?P<request>[^\"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

INJECTION_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("SQL injection", re.compile(r"(?:'|%27)\s*(?:or|and)\s*(?:1|true)\s*=\s*(?:1|true)", re.I)),
    ("SQL union", re.compile(r"(?:union(?:%20|\s)+select)", re.I)),
    ("XSS", re.compile(r"<\s*script\b|%3c\s*script", re.I)),
    ("Path traversal", re.compile(r"(?:\.\./|%2e%2e%2f|%2e%2e/)", re.I)),
    ("Command injection", re.compile(r"(?:;|%3b|\|)\s*(?:bash|sh|cmd|powershell)\b", re.I)),
]


@dataclass
class Threat:
    kind: str
    ip: str
    detail: str
    line: str = ""
    timestamp: Optional[str] = None


@dataclass
class Analysis:
    source: str
    source_type: str
    total_lines: int = 0
    ssh_failures: Counter[str] = field(default_factory=Counter)
    ssh_successes: Counter[str] = field(default_factory=Counter)
    web_requests: Counter[str] = field(default_factory=Counter)
    status_codes: Counter[str] = field(default_factory=Counter)
    threats: list[Threat] = field(default_factory=list)
    rule_counts: Counter[str] = field(default_factory=Counter)

    @property
    def critical_ips(self) -> list[tuple[str, int]]:
        scores = Counter()
        for threat in self.threats:
            scores[threat.ip] += 1
        return scores.most_common()


def detect_source(lines: Iterable[str]) -> str:
    for line in lines:
        if SSH_FAILURE_RE.search(line) or SSH_ACCEPTED_RE.search(line):
            return "ssh"
        if WEB_RE.match(line):
            return "web"
    return "unknown"


def parse_ssh_line(line: str) -> tuple[str, str] | None:
    match = SSH_FAILURE_RE.search(line)
    if match:
        return "failure", match.group("ip")
    match = SSH_ACCEPTED_RE.search(line)
    if match:
        return "success", match.group("ip")
    return None


def parse_web_line(line: str) -> tuple[str, str, str, str] | None:
    match = WEB_RE.match(line)
    if not match:
        return None
    return match.group("ip"), match.group("date"), match.group("request"), match.group("status")


def analyze_lines(lines: Iterable[str], source: str, source_type: str, threshold: int, window: int) -> Analysis:
    result = Analysis(source=source, source_type=source_type)
    failure_times: dict[str, deque[int]] = defaultdict(deque)
    all_lines = list(lines)

    if source_type == "auto":
        source_type = detect_source(all_lines)
        result.source_type = source_type

    for index, raw_line in enumerate(all_lines):
        line = raw_line.rstrip("\n")
        if not line:
            continue
        result.total_lines += 1

        if source_type == "ssh":
            parsed = parse_ssh_line(line)
            if not parsed:
                continue
            kind, ip = parsed
            if kind == "success":
                result.ssh_successes[ip] += 1
                continue

            result.ssh_failures[ip] += 1
            q = failure_times[ip]
            q.append(index)
            while q and index - q[0] >= window:
                q.popleft()
            if len(q) >= threshold:
                result.threats.append(
                    Threat(
                        kind="SSH brute force",
                        ip=ip,
                        detail=f"{len(q)} falhas dentro da janela de {window} linhas",
                        line=line,
                    )
                )

        elif source_type == "web":
            parsed = parse_web_line(line)
            if not parsed:
                continue
            ip, timestamp, request, status = parsed
            result.web_requests[ip] += 1
            result.status_codes[status] += 1
            for name, pattern in INJECTION_RULES:
                if pattern.search(request):
                    result.rule_counts[name] += 1
                    result.threats.append(
                        Threat(
                            kind=name,
                            ip=ip,
                            detail=f"requisição suspeita: {request[:180]}",
                            line=line,
                            timestamp=timestamp,
                        )
                    )

    # Remove repeated threshold hits for the same IP down to one summary threat.
    if source_type == "ssh":
        unique: dict[str, Threat] = {}
        for threat in result.threats:
            unique.setdefault(threat.ip, threat)
        result.threats = list(unique.values())

    return result


def analyze_file(path: Path, source_type: str, threshold: int, window: int, follow: bool = False):
    if not path.exists():
        raise FileNotFoundError(path)

    if follow:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
            result = analyze_lines(lines, str(path), source_type, threshold, window)
            while True:
                new_lines = handle.readlines()
                if new_lines:
                    result = analyze_lines(lines + new_lines, str(path), source_type, threshold, window)
                    lines.extend(new_lines)
                time.sleep(1)
    else:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return analyze_lines(handle, str(path), source_type, threshold, window)


def render_text(result: Analysis) -> str:
    lines = [
        "LOG ANALYZER",
        "=" * 60,
        f"Arquivo: {result.source}",
        f"Tipo: {result.source_type}",
        f"Linhas analisadas: {result.total_lines}",
        "",
        "AMEAÇAS",
        "-" * 60,
    ]
    if not result.threats:
        lines.append("Nenhuma ameaça encontrada pelas regras atuais.")
    else:
        for threat in result.threats:
            lines.append(f"[{threat.kind}] {threat.ip} - {threat.detail}")

    lines += ["", "IPS MAIS CRÍTICOS", "-" * 60]
    critical = result.critical_ips
    if critical:
        for ip, score in critical[:10]:
            lines.append(f"{ip}: {score} alerta(s)")
    else:
        lines.append("Nenhum IP marcado.")

    if result.source_type == "ssh":
        lines += [
            "", "SSH", "-" * 60,
            f"Falhas por IP: {dict(result.ssh_failures)}",
            f"Logins aceitos por IP: {dict(result.ssh_successes)}",
        ]
    elif result.source_type == "web":
        lines += [
            "", "WEB", "-" * 60,
            f"Requisições por IP: {dict(result.web_requests)}",
            f"Status HTTP: {dict(result.status_codes)}",
            f"Regras disparadas: {dict(result.rule_counts)}",
        ]
    return "\n".join(lines) + "\n"


def render_html(result: Analysis) -> str:
    threat_rows = "".join(
        f"<tr><td>{html.escape(t.kind)}</td><td>{html.escape(t.ip)}</td>"
        f"<td>{html.escape(t.detail)}</td><td>{html.escape(t.timestamp or '-')}</td></tr>"
        for t in result.threats
    ) or '<tr><td colspan="4">Nenhuma ameaça encontrada.</td></tr>'

    critical_rows = "".join(
        f"<tr><td>{html.escape(ip)}</td><td>{score}</td></tr>" for ip, score in result.critical_ips[:10]
    ) or '<tr><td colspan="2">Nenhum IP marcado.</td></tr>'

    return f"""<!doctype html>
<html lang="pt-BR">
<head><meta charset="utf-8"><title>Log Analyzer</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;background:#f6f6f6;color:#222}}
.card{{background:#fff;border:1px solid #ddd;border-radius:12px;padding:20px;margin:16px 0}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}
code{{background:#eee;padding:2px 5px;border-radius:4px}}
</style></head>
<body><h1>Log Analyzer</h1>
<div class="card"><p><strong>Arquivo:</strong> {html.escape(result.source)}</p><p><strong>Tipo:</strong> {html.escape(result.source_type)}</p><p><strong>Linhas:</strong> {result.total_lines}</p></div>
<div class="card"><h2>Ameaças</h2><table><thead><tr><th>Tipo</th><th>IP</th><th>Detalhe</th><th>Data</th></tr></thead><tbody>{threat_rows}</tbody></table></div>
<div class="card"><h2>IPs mais críticos</h2><table><thead><tr><th>IP</th><th>Alertas</th></tr></thead><tbody>{critical_rows}</tbody></table></div>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analisa logs SSH, Apache e Nginx.")
    parser.add_argument("arquivo", type=Path, help="arquivo de log")
    parser.add_argument("--type", choices=["auto", "ssh", "web"], default="auto", dest="source_type")
    parser.add_argument("--threshold", type=int, default=5, help="falhas necessárias para marcar brute force")
    parser.add_argument("--window", type=int, default=20, help="janela em linhas usada no brute force")
    parser.add_argument("--html", type=Path, help="salva também um relatório HTML")
    parser.add_argument("--txt", type=Path, help="salva um relatório TXT")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = analyze_file(args.arquivo, args.source_type, args.threshold, args.window)
    text = render_text(result)
    print(text)

    if args.txt:
        args.txt.write_text(text, encoding="utf-8")
    if args.html:
        args.html.write_text(render_html(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
