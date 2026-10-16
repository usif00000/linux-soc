# Wireshark SOC Analyzer

A Python-based network traffic analysis tool that uses TShark to inspect PCAP/PCAPNG files, identify suspicious network patterns, and generate JSON and HTML reports for SOC analyst review.

## Features

- Extract packet metadata, IP addresses, protocol labels, TCP flags, and DNS queries.
- Detect possible TCP port scans using distinct destination-port counts.
- Identify repeated DNS queries and high TCP reset counts.
- Assign heuristic alert severity levels.
- Generate structured JSON and human-readable HTML reports.
- Provide evidence and recommended analyst investigation steps.

## Technology Stack

- Python 3
- Wireshark / TShark
- JSON
- HTML and CSS
- Kali Linux

## Requirements

- Python 3
- TShark installed and available on your PATH
- A PCAP or PCAPNG file that you are authorized to analyze

## Installation

```bash
git clone https://github.com/usif00000/linux-soc.git
cd linux-soc
```

Install TShark on Kali Linux if needed:

```bash
sudo apt update
sudo apt install tshark
```

Check the installation:

```bash
python3 --version
tshark --version
```

## Usage

Capture new network traffic

To capture traffic from your Wi-Fi interface for 30 seconds:
```bash
timeout 30s tshark -i wlan0 -w captures/new-capture.pcap

Analyze a capture file:

```bash
python3 analyzer.py captures/scan-test.pcap
```

Open the generated HTML report:

```bash
xdg-open reports/analysis.html
```

The analyzer writes its reports to the `reports/` directory. Each run updates the report files, so preserve copies if you need historical results.

## Current Detection Rules

| Detection | Rule |
|---|---|
| Possible TCP port scan | At least 10 distinct destination ports receive initial TCP SYN attempts for a source/destination pair |
| High-frequency DNS query | The same DNS name is queried at least 20 times |
| Many TCP resets | At least 20 TCP reset packets are associated with a source IP |

These thresholds are heuristic examples, not definitive indicators of compromise.

## Validation

The project has been tested with a normal network capture and a controlled localhost Nmap scan. The scan test produced a possible port-scan alert and a TCP-reset alert.

Additional automated tests and broader validation are planned.

## Limitations

- An alert does not prove malicious activity.
- Detection depends on capture quality and the implemented rules.
- Encrypted traffic limits visibility into application payloads.
- The tool analyzes supplied captures; continuous monitoring and automated blocking are not currently provided.

## Safe Use

Analyze only network traffic that you own or are authorized to inspect. Sanitize captures before sharing them publicly.

## Future Improvements

- Automated unit and integration tests
- Event timestamps and time-window-based detection
- Configurable thresholds
- Better alert deduplication and investigation context
- Integration with a SIEM or SOC alert-triage platform

## Author

Muhammad Usama Khursheed

Cybersecurity | Network Traffic Analysis | SOC Analyst Learning Projects
