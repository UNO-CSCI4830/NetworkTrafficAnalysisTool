# Network/Malware Analysis Tool

A semantic network traffic analysis tool that converts raw connection data into plain-English explanations. Identifies active network connections, enriches them with port/process metadata, scores risk, and generates readable reports for both technical and nontechnical audiences.

## Quick Start

```bash
python main.py
```

This collects live network connections from the machine, runs the analysis pipeline, prints a summary to the terminal, and generates `report.html`.

## Project Structure

```
network-analysis-tool/
├── README.md
├── main.py
├── data/
│   ├── known_ports.json
│   └── known_processes.json
└── src/
    ├── collector.py
    ├── enrichment.py
    ├── risk_scorer.py
    ├── summary.py
    └── report.py
```

| File | What it does |
|------|-------------|
| `main.py` | CLI entry point which runs the pipeline and writes output |
| `data/known_ports.json` | Port → service name/description lookup |
| `data/known_processes.json` | Whitelist of known-good Windows processes and their expected ports |
| `src/collector.py` | Collects live network connections via psutil and returns normalized dicts |
| `src/enrichment.py` | Port and process enrichment |
| `src/risk_scorer.py` | Scores each connection 0–100 based on weighted threat indicators |
| `src/summary.py` | Generates plain-English descriptions of each connection |
| `src/report.py` | Builds a self-contained HTML report with color-coded risk table |

## Pipeline

```
Live Connections via psutil → Enrichment → Risk Scoring → Summary Generation → HTML Report
```

## Team

| Name | Role |
|------|------|
| Niko L. | Project Manager / Team Coordinator |
| Daniel M. | Network Data / Packet Developer |
| Jai P. | Semantic / AI Logic Developer |
| Evan C. | Interface / UI Developer |
| Landon M. | Testing / Documentation Lead |
| Blake B. | UX Designer / User Experience |
| Andrew W. | Threat Intelligence / Detection Engineering |

## Requirements
- Python 3.10+
- psutil