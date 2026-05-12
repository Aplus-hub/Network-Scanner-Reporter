import os
import datetime
from jinja2 import Environment, FileSystemLoader
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class Reporter:
    def __init__(self, template_dir='.'):
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template_name = 'report_template.html'

    def generate_html_report(self, target, scan_results, output_file='vulnerability_report.html'):
        """
        Generates an HTML report from the scan results.
        :param target: The original target string
        :param scan_results: The processed results dictionary containing hosts and vulnerabilities
        :param output_file: Path to save the HTML file
        """
        try:
            template = self.env.get_template(self.template_name)
            
            # Prepare data
            data = {
                'target': target,
                'scan_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'hosts': scan_results
            }
            
            html_content = template.render(data)
            
            with open(output_file, 'w') as f:
                f.write(html_content)
                
            logging.info(f"Report generated successfully: {output_file}")
            
        except Exception as e:
            logging.error(f"Error generating report: {e}")

if __name__ == "__main__":
    # Test
    dummy_results = [
        {
            'host': '192.168.1.1',
            'state': 'up',
            'protocols': {
                'tcp': [
                    {
                        'port': 80,
                        'name': 'http',
                        'state': 'open',
                        'product': 'Apache httpd',
                        'version': '2.4.49',
                        'cpe': 'cpe:/a:apache:http_server:2.4.49',
                        'vulnerabilities': [
                            {'id': 'CVE-2021-41773', 'severity': 'CRITICAL', 'score': '9.8', 'description': 'Path traversal vulnerability...'}
                        ]
                    }
                ]
            }
        }
    ]
    reporter = Reporter()
    reporter.generate_html_report("192.168.1.1", dummy_results, "test_report.html")
