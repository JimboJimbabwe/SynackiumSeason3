#!/usr/bin/env python3
"""
Burp Suite XML Analyzer
-----------------------
This script parses Burp Suite XML files to identify web server headers
and their values, counts occurrences of identical headers, and provides
a list of common admin interfaces for cloud platforms.
"""

import xml.etree.ElementTree as ET
import base64
import argparse
import re
from collections import defaultdict, Counter
import sys

class BurpXMLAnalyzer:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.headers_data = defaultdict(list)
        self.header_counts = defaultdict(Counter)
        
    def parse_xml(self):
        """Parse the Burp Suite XML file."""
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()
            return root
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"File not found: {self.xml_file}")
            sys.exit(1)
    
    def decode_base64(self, encoded_text):
        """Decode base64 encoded text."""
        try:
            return base64.b64decode(encoded_text).decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Error decoding base64: {e}")
            return None
    
    def extract_headers(self, response_text):
        """Extract headers from response text."""
        headers = {}
        # Find the headers section (ends with double newline)
        header_section = response_text.split('\r\n\r\n')[0] if '\r\n\r\n' in response_text else response_text
        
        # Parse each header line
        for line in header_section.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers
    
    def analyze(self):
        """Analyze the XML file for web server headers."""
        root = self.parse_xml()
        if not root:
            return
        
        # Process each item in the XML
        for item in root.findall('.//item'):
            # Extract response if available
            response = item.find('.//response')
            if response is None or not response.text:
                continue
            
            # Decode response
            response_text = self.decode_base64(response.text)
            if not response_text:
                continue
            
            # Get URL from request if available
            request = item.find('.//request')
            url = "Unknown URL"
            if request is not None:
                request_text = self.decode_base64(request.text)
                if request_text:
                    first_line = request_text.split('\r\n')[0]
                    url_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.+) HTTP', first_line)
                    if url_match:
                        path = url_match.group(2)
                        host_header = re.search(r'Host: (.+)', request_text)
                        if host_header:
                            host = host_header.group(1).strip()
                            url = f"{host}{path}"
            
            # Extract headers
            headers = self.extract_headers(response_text)
            
            # Look for web server headers
            server_headers = [
                'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
                'x-server', 'x-runtime', 'x-version', 'powered-by', 'x-generator',
                'x-framework', 'x-content-powered-by', 'x-ua-compatible',
                'x-middleton-version', 'x-hudson', 'x-jenkins', 'x-rack-cache',
                'x-drupal-version', 'x-drupal-dynamic-cache', 'x-drupal-cache',
                'x-hosted-by', 'x-backend-server', 'cf-ray', 'x-amz-cf-id',
                'x-azure-ref', 'x-ms-version', 'x-goog-*'
            ]
            
            for header_name in headers:
                # Check for exact matches
                if header_name in server_headers:
                    self.headers_data[header_name].append({'url': url, 'value': headers[header_name]})
                    self.header_counts[header_name][headers[header_name]] += 1
                # Check for wildcard matches
                elif any(h.endswith('*') and header_name.startswith(h[:-1]) for h in server_headers):
                    self.headers_data[header_name].append({'url': url, 'value': headers[header_name]})
                    self.header_counts[header_name][headers[header_name]] += 1
    
    def print_results(self):
        """Print the analysis results."""
        if not self.headers_data:
            print("No web server headers found.")
            return
        
        print("\n" + "="*80)
        print("WEB SERVER HEADERS ANALYSIS")
        print("="*80)
        
        for header, data in sorted(self.headers_data.items()):
            print(f"\n[+] Header: {header}")
            print("-" * 50)
            
            # Group by value and count occurrences
            values_count = self.header_counts[header]
            
            for value, count in values_count.items():
                print(f"  Value: {value}")
                print(f"  Count: {count}")
                
                # Print up to 5 sample URLs for this header value
                url_samples = [item['url'] for item in data if item['value'] == value][:5]
                if url_samples:
                    print("  Sample URLs:")
                    for url in url_samples:
                        print(f"    - {url}")
                
                print("-" * 40)
        
        print("\n")


def print_admin_interfaces():
    """Print a list of common admin interfaces for cloud platforms."""
    admin_interfaces = {
        "AWS (Amazon Web Services)": [
            "/aws/console/", 
            "/console.aws.amazon.com/",
            "/aws-management/",
            "/aws-admin/",
            "/aws-console/",
            "/cloudformation-console/",
            "/aws/s3/console/",
            "/ec2-console/",
            "/lambda-console/",
            "/dynamodb-console/",
            "/rds-console/",
            "/iam-console/",
            "/route53-console/",
            "/aws/cognito/",
            "/aws-apigateway-console/",
            "/elasticbeanstalk-console/",
            "/s3-console/",
            "/cloudwatch-console/",
            "/ecs-console/",
            "/eks-console/",
            "/aws-fargate-console/",
            "/sagemaker-console/",
            "/glue-console/",
            "/emr-console/",
            "/athena-console/",
            "/quicksight-console/"
        ],
        "GCP (Google Cloud Platform)": [
            "/cloud.google.com/console/",
            "/gcp-console/",
            "/google-cloud-console/",
            "/gcp-admin/",
            "/google-cloud-admin/",
            "/appengine-admin/",
            "/compute-engine-console/",
            "/gcp/storage/",
            "/cloud-sql-admin/",
            "/firebase-console/",
            "/gcp-kubernetes-engine/",
            "/gcp/bigquery/",
            "/cloud-dataflow-console/",
            "/cloud-dataproc-console/",
            "/cloud-iam-admin/",
            "/gcp/app-engine/",
            "/gcp/monitoring/",
            "/stackdriver-console/",
            "/gcp/cloud-run/",
            "/gcp/cloud-functions/",
            "/gcp/cloud-scheduler/",
            "/gcp/cloud-tasks/",
            "/gcp/cloud-pubsub/",
            "/gcp/anthos/",
            "/cloud-spanner-admin/"
        ],
        "Microsoft Azure": [
            "/azure-portal/",
            "/portal.azure.com/",
            "/azure-admin/",
            "/azure-management/",
            "/azure-resources/",
            "/azure-console/",
            "/azure-vm-console/",
            "/azure-storage-admin/",
            "/azure-sql-admin/",
            "/azure-app-service/",
            "/azure-functions-admin/",
            "/azure-active-directory/",
            "/azure-ad-admin/",
            "/azure-devops-console/",
            "/azure-kubernetes-service/",
            "/azure-cosmos-db/",
            "/azure-api-management/",
            "/azure-logic-apps/",
            "/azure-databricks-console/",
            "/azure-data-factory/",
            "/azure-event-hub/",
            "/azure-service-bus/",
            "/azure-iot-hub/",
            "/azure-monitor/",
            "/azure-security-center/"
        ],
        "Other Cloud Platforms": [
            "/digitalocean/console/",
            "/droplet-console/",
            "/linode-console/",
            "/linode-manager/",
            "/vultr-console/",
            "/heroku-dashboard/",
            "/ibm-cloud-console/",
            "/oracle-cloud-console/",
            "/oci-console/",
            "/openstack-dashboard/",
            "/openstack-horizon/",
            "/cloudfoundry-console/",
            "/pivotal-console/",
            "/scaleway-console/",
            "/hetzner-cloud-console/",
            "/cloudflare-dashboard/",
            "/alibabacloud-console/",
            "/aliyun-console/",
            "/tencent-cloud-console/",
            "/rackspace-cloud-control/",
            "/ovh-manager/",
            "/upcloud-control-panel/",
            "/netlify-admin/"
        ]
    }
    
    print("\n" + "="*80)
    print("COMMON ADMIN INTERFACES")
    print("="*80)
    
    for platform, interfaces in admin_interfaces.items():
        print(f"\n[+] {platform}")
        print("-" * 50)
        for i, interface in enumerate(interfaces, 1):
            print(f"  {i}. {interface}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Analyze Burp Suite XML files for web server headers")
    parser.add_argument("xml_file", help="Path to the Burp Suite XML file")
    parser.add_argument("--admin-interfaces", action="store_true", help="Print common admin interfaces")
    args = parser.parse_args()
    
    analyzer = BurpXMLAnalyzer(args.xml_file)
    analyzer.analyze()
    analyzer.print_results()
    
    if args.admin_interfaces:
        print_admin_interfaces()


if __name__ == "__main__":
    main()
