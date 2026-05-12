# Automated Network Scanner & Vulnerability Reporter

A Python-based Command-Line Interface (CLI) tool that automates network scanning, service discovery, and vulnerability assessment. It uses `nmap` to discover open ports and services, correlates those services with the National Vulnerability Database (NVD) via their REST API, and generates a clean, readable HTML report of the findings.

## Features

- **Automated Service Discovery**: Uses `nmap` (with `-sV` version detection) to scan IP addresses, domains, or subnets.
- **Vulnerability Correlation**: Automatically queries the NIST NVD API to find known CVEs (Common Vulnerabilities and Exposures) matching the discovered services.
- **HTML Reporting**: Generates an easy-to-read HTML report detailing open ports, running services, and associated vulnerabilities (including CVSS scores and severities).
- **Rate-Limit Aware**: Includes built-in delays for NVD API queries to prevent IP bans, with optional support for NVD API keys to significantly speed up scans.

## Prerequisites

1. **Nmap**: You must have `nmap` installed on your system.
   - macOS: `brew install nmap`
   - Linux (Debian/Ubuntu): `sudo apt install nmap`
2. **Python 3.x**: Ensure Python 3 is installed.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/network-scanner-reporter.git
   cd network-scanner-reporter
   ```

2. Create a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the scanner using `main.py`. You must provide a target IP, hostname, or subnet.

```bash
python main.py <target> [options]
```

### Examples

**Basic scan (Top 1000 ports):**
```bash
python main.py scanme.nmap.org
```

**Scan specific ports:**
```bash
python main.py 192.168.1.1 -p 22,80,443
```

**Speed up vulnerability lookups with an NVD API Key:**
*(If you don't use an API key, the script will wait 6 seconds between NVD queries to respect strict rate limits. You can get a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key)).*
```bash
python main.py scanme.nmap.org -k YOUR_API_KEY
```

**Output to a specific file name:**
```bash
python main.py scanme.nmap.org -o my_custom_report.html
```

## Disclaimer

This tool is designed for educational and defensive purposes only. **Do not** use this tool to scan networks or IP addresses that you do not own or do not have explicit permission to test.
