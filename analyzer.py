#!/usr/bin/env python3
import argparse
import csv
import json
import shutil
import subprocess
import sys
import html
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPORT_DIR = BASE / "reports"

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "_ws.col.Protocol",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset",
    "dns.qry.name", "dns.flags.response", "dns.flags.rcode",
]


def analyze(pcap):
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("TShark not found. Install Wireshark/TShark first.")

    command = [
        tshark, "-n", "-r", str(pcap), "-T", "fields",
        "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for field in FIELDS:
        command.extend(["-e", field])

    result = subprocess.run(
        command, capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark failed to read the capture.")

    packets = []
    for line in result.stdout.splitlines():
        values = line.split("\t")
        values += [""] * (len(FIELDS) - len(values))
        packets.append(dict(zip(FIELDS, values[:len(FIELDS)])))

    protocols = Counter()
    sources = Counter()
    destinations = Counter()
    dns_queries = Counter()
    syn_ports = defaultdict(set)
    reset_sources = Counter()
    syn_attempts = Counter()
    syn_destinations = Counter()

    packet_count = len(packets)

    for p in packets:
        protocol = p["_ws.col.Protocol"] or "Unknown"
        protocols[protocol] += 1

        src = p["ip.src"] or p["ipv6.src"]
        dst = p["ip.dst"] or p["ipv6.dst"]
        if src:
            sources[src] += 1
        if dst:
            destinations[dst] += 1

        # Record initial TCP SYN attempts as connection evidence.
        is_syn = p["tcp.flags.syn"].lower() in ("true", "1")
        is_ack = p["tcp.flags.ack"].lower() in ("true", "1")

        if src and dst and is_syn and not is_ack and p["tcp.dstport"]:
            destination_port = p["tcp.dstport"]
            syn_ports[(src, dst)].add(destination_port)
            syn_attempts[(src, dst, destination_port)] += 1
            syn_destinations[dst] += 1

        if src and p["tcp.flags.reset"].lower() in ("true", "1"):
            reset_sources[src] += 1

        query = p["dns.qry.name"].strip()
        if query and p["dns.flags.response"] == "0":
            dns_queries[query] += 1

    findings = []
    for (src, dst), ports in sorted(syn_ports.items()):
        if len(ports) >= 10:
            findings.append({
                "type": "possible_port_scan",
                "severity": "medium",
                "source_ip": src,
                "destination_ip": dst,
                "distinct_destination_ports": len(ports),
                "ports": sorted(ports, key=lambda x: int(x)),
                "evidence": "At least 10 distinct destination ports received initial TCP SYN attempts.",
                "note": "Heuristic only; legitimate activity and incomplete captures can produce similar patterns."
            })

    for domain, count in dns_queries.most_common():
        if count >= 20:
            findings.append({
                "type": "high_frequency_dns_query",
                "severity": "low",
                "domain": domain,
                "query_count": count,
                "evidence": "The same DNS name was queried at least 20 times.",
                "note": "Could be normal application behavior; investigate context."
            })

    for src, count in reset_sources.most_common():
        if count >= 20:
            findings.append({
                "type": "many_tcp_resets",
                "severity": "low",
                "source_ip": src,
                "reset_count": count,
                "evidence": "At least 20 TCP reset packets had this source IP.",
                "note": "Resets can result from ordinary application or network issues."
            })

    report = {
        "tool": "Wireshark SOC Analyzer",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capture_file": pcap.name,
        "packet_count": packet_count,
        "tcp_syn_attempt_count": sum(syn_attempts.values()),
        "tcp_syn_destination_summary": [
            {"destination_ip": dst, "attempt_count": count}
            for dst, count in syn_destinations.most_common(10)
        ],
        "protocols": dict(protocols.most_common()),
        "top_source_ips": sources.most_common(10),
        "top_destination_ips": destinations.most_common(10),
        "top_dns_queries": dns_queries.most_common(20),
        "findings_count": len(findings),
        "findings": findings,
        "limitations": [
            "Findings are heuristic leads, not proof of malicious activity.",
            "Encrypted application payloads generally cannot be inspected without authorized decryption.",
            "Missing packets or unsupported protocols can affect results."
        ]
    }
    return report




def analyst_recommendations(finding):
    """Return practical next steps based on the alert type."""
    alert_type = finding.get("type", "")

    if alert_type == "possible_port_scan":
        return [
            "Verify whether the source host and scan activity are authorized.",
            "Review the targeted ports and identify services listening on the destination.",
            "Correlate the event with firewall, endpoint, and authentication logs.",
            "Check surrounding traffic for successful connections or follow-on activity.",
            "Document the result as authorized testing, suspicious activity, or inconclusive."
        ]

    if alert_type == "many_tcp_resets":
        return [
            "Check whether the reset packets relate to a known scan or application behavior.",
            "Review source and destination addresses and the affected ports.",
            "Correlate with firewall and endpoint logs before treating the activity as malicious.",
            "Record whether the resets are expected, recurring, or unexplained."
        ]

    if alert_type == "high_frequency_dns_query":
        return [
            "Confirm which host generated the repeated DNS queries, if that data is available.",
            "Review the queried domain and query timing.",
            "Check DNS resolver logs and endpoint telemetry for additional context.",
            "Look for unusual domains or related connections before escalating."
        ]

    return [
        "Validate the alert evidence and capture completeness.",
        "Identify the affected hosts and review relevant security logs.",
        "Correlate with other telemetry before determining severity.",
        "Document the investigation and its outcome."
    ]


def render_html(report):
    """Render the JSON analysis as a readable, escaped HTML report."""
    esc = lambda value: html.escape(str(value))

    protocol_rows = "".join(
        f"<tr><td>{esc(name)}</td><td>{count}</td></tr>"
        for name, count in report["protocols"].items()
    ) or '<tr><td colspan="2">No protocol data</td></tr>'

    def ip_rows(items):
        return "".join(
            f"<tr><td>{esc(ip)}</td><td>{count}</td></tr>"
            for ip, count in items
        ) or '<tr><td colspan="2">No data</td></tr>'

    syn_rows = "".join(
        f"<tr><td>{esc(item['destination_ip'])}</td>"
        f"<td>{item['attempt_count']}</td></tr>"
        for item in report.get("tcp_syn_destination_summary", [])
    ) or '<tr><td colspan="2">No initial TCP SYN attempts recorded</td></tr>'

    finding_cards = []
    for finding in report["findings"]:
        severity = esc(finding.get("severity", "unknown")).lower()
        details = []
        for key in (
            "source_ip", "destination_ip", "domain",
            "distinct_destination_ports", "reset_count",
            "query_count"
        ):
            if key in finding:
                details.append(
                    f"<li><strong>{esc(key.replace('_', ' ').title())}:</strong> "
                    f"{esc(finding[key])}</li>"
                )

        actions = analyst_recommendations(finding)
        details.append(
            "<li><strong>Recommended analyst actions:</strong><ol>"
            + "".join(f"<li>{esc(action)}</li>" for action in actions)
            + "</ol></li>"
        )

        ports = finding.get("ports")
        if ports:
            details.append(
                f"<li><strong>Ports:</strong> {esc(', '.join(ports))}</li>"
            )

        finding_cards.append(f"""
        <article class="finding">
          <span class="badge {severity}">{severity.upper()}</span>
          <h3>{esc(finding.get('type', 'Unknown finding'))}</h3>
          <ul>{''.join(details)}</ul>
          <p><strong>Evidence:</strong> {esc(finding.get('evidence', 'Not provided'))}</p>
          <p><strong>Analyst note:</strong> {esc(finding.get('note', 'Review context'))}</p>
        </article>
        """)

    findings_html = "".join(finding_cards) or (
        '<p class="empty">No findings were generated for this capture. '
        'This does not guarantee the capture is free of threats.</p>'
    )

    limitations = "".join(
        f"<li>{esc(item)}</li>" for item in report.get("limitations", [])
    )

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Analysis - {esc(report['capture_file'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 0; background: #f3f5f8; color: #172033; }}
main {{ max-width: 1050px; margin: auto; padding: 24px; }}
header, section, .finding {{ background: white; border: 1px solid #dce2ea; border-radius: 12px; padding: 20px; margin-bottom: 18px; }}
h1 {{ margin-top: 0; }} h2 {{ margin-top: 0; }}
.muted {{ color: #5b6575; overflow-wrap: anywhere; }}
.stats {{ display: flex; flex-wrap: wrap; gap: 12px; }}
.stat {{ flex: 1; min-width: 150px; background: #edf2f8; padding: 16px; border-radius: 8px; }}
.stat strong {{ display: block; font-size: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 9px; border-bottom: 1px solid #e1e6ed; overflow-wrap: anywhere; }}
.finding h3 {{ margin-bottom: 8px; }} .finding ul {{ overflow-wrap: anywhere; }}
.badge {{ display: inline-block; border-radius: 5px; padding: 4px 8px; font-weight: 700; font-size: .8rem; background: #e8edf3; }}
.badge.medium {{ background: #fff0c2; }} .badge.high, .badge.critical {{ background: #ffd9d9; }}
.badge.low {{ background: #e2edff; }} .empty {{ padding: 12px; }}
footer {{ color: #5b6575; font-size: .9rem; padding: 8px 0 24px; }}
@media (max-width: 600px) {{ main {{ padding: 12px; }} header, section, .finding {{ padding: 14px; }} }}
</style>
</head>
<body><main>
<header>
<h1>Wireshark SOC Analyzer</h1>
<p><strong>Capture:</strong> {esc(report['capture_file'])}</p>
<p class="muted">Generated at: {esc(report['generated_at'])}</p>
<div class="stats">
<div class="stat"><strong>{report['packet_count']}</strong>Packets analyzed</div>
<div class="stat"><strong>{len(report['protocols'])}</strong>Protocol labels</div>
<div class="stat"><strong>{report['findings_count']}</strong>Findings</div>
</div>
</header>
<section><h2>Protocol statistics</h2>
<table><thead><tr><th>Protocol label</th><th>Packet count</th></tr></thead>
<tbody>{protocol_rows}</tbody></table></section>
<section><h2>TCP connection evidence</h2>
<p>Initial TCP SYN attempts: <strong>{report.get('tcp_syn_attempt_count', 0)}</strong></p>
<p class="muted">SYN attempts indicate connection attempts; they do not by themselves prove scanning or malicious activity.</p>
<table><thead><tr><th>Destination IP</th><th>SYN attempts</th></tr></thead>
<tbody>{syn_rows}</tbody></table></section>
<section><h2>Security findings</h2>{findings_html}</section>
<section><h2>Top source IPs</h2>
<table><thead><tr><th>IP address</th><th>Packet count</th></tr></thead>
<tbody>{ip_rows(report['top_source_ips'])}</tbody></table></section>
<section><h2>Top destination IPs</h2>
<table><thead><tr><th>IP address</th><th>Packet count</th></tr></thead>
<tbody>{ip_rows(report['top_destination_ips'])}</tbody></table></section>
<section><h2>Frequently observed DNS queries</h2>
<table><thead><tr><th>Domain</th><th>Query count</th></tr></thead>
<tbody>{ip_rows(report['top_dns_queries'])}</tbody></table></section>
<section><h2>Limitations and cautions</h2><ul>{limitations}</ul>
<p>These heuristic findings are leads for analyst review, not proof of malicious activity.</p></section>
<footer>Generated locally by Wireshark SOC Analyzer.</footer>
</main></body></html>"""
    return document


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and generate a basic SOC report."
    )
    parser.add_argument("pcap", help="Path to a PCAP or PCAPNG file")
    args = parser.parse_args()
    pcap = Path(args.pcap).expanduser().resolve()

    if not pcap.is_file():
        parser.error(f"Capture file not found: {pcap}")

    try:
        report = analyze(pcap)
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    output = REPORT_DIR / "analysis.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_output = REPORT_DIR / "analysis.html"
    html_output.write_text(render_html(report), encoding="utf-8")

    print("=== Wireshark SOC Analyzer ===")
    print(f"Capture: {pcap.name}")
    print(f"Packets analyzed: {report['packet_count']}")
    print(f"Initial TCP SYN attempts: {report.get('tcp_syn_attempt_count', 0)}")
    print(f"Protocols: {json.dumps(report['protocols'])}")
    print(f"Findings: {report['findings_count']}")
    for finding in report["findings"]:
        print(f"- [{finding['severity'].upper()}] {finding['type']}: "
              f"{finding.get('source_ip', finding.get('domain', 'see report'))}")
    print(f"JSON report saved to: {output}")
    print(f"HTML report saved to: {html_output}")


if __name__ == "__main__":
    main()
