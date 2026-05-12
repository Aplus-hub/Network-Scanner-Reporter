import argparse
import logging
from scanner import NetworkScanner
from vulnerability_lookup import VulnerabilityLookup
from reporter import Reporter

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    parser = argparse.ArgumentParser(description="Automated Network Scanner & Vulnerability Reporter")
    parser.add_argument("target", help="Target IP address, hostname, or subnet (e.g., 192.168.1.1, scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '22,80,443' or '1-1000'). Default is top 1000.", default=None)
    parser.add_argument("-a", "--args", help="Nmap arguments. Default is '-sV' for version detection.", default='-sV')
    parser.add_argument("-k", "--api-key", help="NVD API Key for faster vulnerability lookups.", default=None)
    parser.add_argument("-o", "--output", help="Output HTML file name.", default='vulnerability_report.html')
    
    args = parser.parse_args()

    # 1. Initialize modules
    scanner = NetworkScanner()
    vuln_lookup = VulnerabilityLookup(api_key=args.api_key)
    reporter = Reporter()

    # 2. Perform Scan
    logging.info(f"--- Starting Scan Phase ---")
    scan_results = scanner.scan(args.target, ports=args.ports, arguments=args.args)

    if not scan_results:
        logging.error("Scan failed or no hosts found. Exiting.")
        return

    # 3. Vulnerability Lookup
    logging.info(f"--- Starting Vulnerability Lookup Phase ---")
    total_ports_with_cpe = 0
    
    for host in scan_results:
        for proto, ports in host.get('protocols', {}).items():
            for port in ports:
                cpe = port.get('cpe')
                if cpe:
                    total_ports_with_cpe += 1
                    vulns = vuln_lookup.lookup_cpe(cpe)
                    port['vulnerabilities'] = vulns
                else:
                    port['vulnerabilities'] = []

    logging.info(f"Completed lookup for {total_ports_with_cpe} services with CPEs.")

    # 4. Generate Report
    logging.info(f"--- Starting Reporting Phase ---")
    reporter.generate_html_report(args.target, scan_results, args.output)
    
    logging.info(f"All done! Open {args.output} to view the results.")

if __name__ == "__main__":
    main()
