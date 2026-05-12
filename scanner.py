import nmap
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logging.error("Nmap not found. Please ensure nmap is installed and in your PATH.")
            raise
        except Exception as e:
            logging.error(f"Unexpected error initializing nmap: {e}")
            raise

    def scan(self, target, ports=None, arguments='-sV'):
        """
        Scan a target IP or subnet.
        :param target: IP address or subnet (e.g., '192.168.1.1', '192.168.1.0/24')
        :param ports: Ports to scan (e.g., '22,80,443', '1-1000')
        :param arguments: Nmap arguments. Default '-sV' for version detection.
        :return: Dictionary of scan results
        """
        logging.info(f"Starting scan on {target}...")
        try:
            self.nm.scan(hosts=target, ports=ports, arguments=arguments)
            results = []
            
            for host in self.nm.all_hosts():
                host_data = {
                    'host': host,
                    'state': self.nm[host].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports_data = []
                    lport = self.nm[host][proto].keys()
                    for port in sorted(lport):
                        port_info = self.nm[host][proto][port]
                        ports_data.append({
                            'port': port,
                            'state': port_info['state'],
                            'name': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', '')
                        })
                    host_data['protocols'][proto] = ports_data
                
                results.append(host_data)
                
            logging.info(f"Scan complete. Found {len(results)} hosts up.")
            return results
            
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return []

if __name__ == "__main__":
    # Simple test
    scanner = NetworkScanner()
    # scanme.nmap.org is a safe test target provided by Nmap
    test_results = scanner.scan('scanme.nmap.org', ports='22,80', arguments='-sV')
    import json
    print(json.dumps(test_results, indent=2))
