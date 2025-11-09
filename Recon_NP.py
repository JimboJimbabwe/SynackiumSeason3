from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (JPanel, JButton, JLabel, JTextArea, JScrollPane, 
                         JSplitPane, BoxLayout, JTextField, JFileChooser,
                         BorderFactory, SwingConstants, JProgressBar)
from java.awt import BorderLayout, GridLayout, Dimension, Color, Font
from java.awt.event import ActionListener
import json
import re
from collections import defaultdict

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Service Wordlist Generator")
        
        # Data storage
        self.server_headers = set()  # Store unique server headers
        self.matched_services = set()  # Store matched service names
        self.matched_endpoints = set()  # Store all matched endpoints
        self.services_data = None  # Will hold loaded JSON data
        self.json_path = ""  # Path to services JSON
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        print("Service Wordlist Generator loaded successfully!")
        print("Please load a services JSON file to begin.")
        print("Use 'Scan History' to analyze existing requests or browse to capture new ones.")
    
    def _create_ui(self):
        """Create the main UI panel"""
        self._main_panel = JPanel(BorderLayout())
        
        # Top panel - JSON file selector
        top_panel = JPanel(BorderLayout())
        top_panel.setBorder(BorderFactory.createTitledBorder("Services JSON Configuration"))
        
        json_panel = JPanel(GridLayout(2, 1, 5, 5))
        
        # JSON path display
        json_path_panel = JPanel(BorderLayout())
        json_path_label = JLabel("JSON File: ")
        self.json_path_field = JTextField()
        self.json_path_field.setEditable(False)
        json_path_panel.add(json_path_label, BorderLayout.WEST)
        json_path_panel.add(self.json_path_field, BorderLayout.CENTER)
        
        # Buttons panel
        buttons_panel = JPanel(GridLayout(1, 2, 5, 5))
        self.load_json_button = JButton("Load Services JSON", actionPerformed=self.load_json_file)
        self.reload_json_button = JButton("Reload JSON", actionPerformed=self.reload_json)
        self.reload_json_button.setEnabled(False)
        buttons_panel.add(self.load_json_button)
        buttons_panel.add(self.reload_json_button)
        
        json_panel.add(json_path_panel)
        json_panel.add(buttons_panel)
        
        top_panel.add(json_panel, BorderLayout.CENTER)
        
        # Middle panel - Statistics and controls
        middle_panel = JPanel()
        middle_panel.setLayout(BoxLayout(middle_panel, BoxLayout.Y_AXIS))
        middle_panel.setBorder(BorderFactory.createTitledBorder("Statistics & Controls"))
        
        # Stats display
        self.stats_label = JLabel("<html><b>Waiting for requests...</b><br>Load a JSON file to begin.</html>")
        self.stats_label.setFont(Font("Dialog", Font.PLAIN, 12))
        middle_panel.add(self.stats_label)
        
        # Action buttons
        action_panel = JPanel(GridLayout(1, 4, 10, 10))
        self.scan_history_button = JButton("Scan History", actionPerformed=self.scan_proxy_history)
        self.generate_button = JButton("Generate Wordlist", actionPerformed=self.generate_wordlist)
        self.generate_button.setEnabled(False)
        self.clear_button = JButton("Clear Data", actionPerformed=self.clear_data)
        self.export_button = JButton("Export to File", actionPerformed=self.export_wordlist)
        self.export_button.setEnabled(False)
        
        action_panel.add(self.scan_history_button)
        action_panel.add(self.generate_button)
        action_panel.add(self.clear_button)
        action_panel.add(self.export_button)
        middle_panel.add(action_panel)
        
        # Split pane for matched services and endpoints
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Left panel - Detected server headers
        left_panel = JPanel(BorderLayout())
        left_panel.setBorder(BorderFactory.createTitledBorder("Detected Server Headers"))
        
        self.headers_text = JTextArea()
        self.headers_text.setEditable(False)
        self.headers_text.setLineWrap(True)
        self.headers_text.setWrapStyleWord(True)
        headers_scroll = JScrollPane(self.headers_text)
        left_panel.add(headers_scroll, BorderLayout.CENTER)
        
        # Right panel - Matched endpoints preview
        right_panel = JPanel(BorderLayout())
        right_panel.setBorder(BorderFactory.createTitledBorder("Generated Wordlist Preview"))
        
        self.endpoints_text = JTextArea()
        self.endpoints_text.setEditable(False)
        self.endpoints_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        endpoints_scroll = JScrollPane(self.endpoints_text)
        right_panel.add(endpoints_scroll, BorderLayout.CENTER)
        
        split_pane.setLeftComponent(left_panel)
        split_pane.setRightComponent(right_panel)
        split_pane.setDividerLocation(400)
        
        # Add all panels to main panel
        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(middle_panel, BorderLayout.CENTER)
        self._main_panel.add(split_pane, BorderLayout.SOUTH)
        
        # Set preferred sizes
        middle_panel.setPreferredSize(Dimension(800, 120))
        split_pane.setPreferredSize(Dimension(800, 400))
    
    def getTabCaption(self):
        return "Wordlist Gen"
    
    def getUiComponent(self):
        return self._main_panel
    
    def load_json_file(self, event):
        """Open file chooser to load services JSON"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Services JSON File")
        
        ret = chooser.showOpenDialog(self._main_panel)
        
        if ret == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            self._load_services_json(file_path)
    
    def reload_json(self, event):
        """Reload the current JSON file"""
        if self.json_path:
            self._load_services_json(self.json_path)
    
    def _load_services_json(self, json_path):
        """Load services JSON file"""
        try:
            with open(json_path, 'r') as f:
                self.services_data = json.load(f)
            
            self.json_path = json_path
            self.json_path_field.setText(json_path)
            self.reload_json_button.setEnabled(True)
            self.generate_button.setEnabled(True)
            
            # Count services
            total_services = 0
            total_ports = len(self.services_data.get('Ports', []))
            
            for port in self.services_data.get('Ports', []):
                total_services += len(port.get('PotentialServices', []))
            
            print("Loaded services JSON: {}".format(json_path))
            print("  Ports: {}".format(total_ports))
            print("  Services: {}".format(total_services))
            
            self._update_stats()
            
        except Exception as e:
            print("Error loading JSON file: {}".format(str(e)))
            self.services_data = None
            self.json_path = ""
            self.json_path_field.setText("Error loading file")
    
    def scan_proxy_history(self, event):
        """Scan all existing requests in Proxy history"""
        print("\n" + "="*60)
        print("SCANNING PROXY HISTORY")
        print("="*60)
        
        # Get all proxy history items
        proxy_history = self._callbacks.getProxyHistory()
        
        if not proxy_history:
            print("No items found in proxy history")
            return
        
        print("Found {} items in proxy history".format(len(proxy_history)))
        print("Extracting server headers...")
        
        before_count = len(self.server_headers)
        processed = 0
        
        for item in proxy_history:
            response = item.getResponse()
            if response is None:
                continue
            
            # Get response headers
            response_info = self._helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            
            # Extract server information
            server_info = self._extract_server_info(headers)
            
            if server_info:
                self.server_headers.update(server_info)
                processed += 1
        
        after_count = len(self.server_headers)
        new_headers = after_count - before_count
        
        print("Processed {} responses with server information".format(processed))
        print("Found {} new unique headers".format(new_headers))
        print("Total unique headers: {}".format(after_count))
        
        # Update UI
        self._update_headers_display()
        self._update_stats()
        
        # Auto-match if JSON is loaded
        if self.services_data:
            print("\nMatching against services...")
            self._match_services()
            print("Matched {} services".format(len(self.matched_services)))
            print("Generated {} endpoints".format(len(self.matched_endpoints)))
        else:
            print("\nNo services JSON loaded - load one to match services")
        
        print("="*60 + "\n")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process each HTTP message (real-time monitoring)"""
        if messageIsRequest:
            return
        
        response = messageInfo.getResponse()
        if response is None:
            return
        
        # Get response headers
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        # Extract server information from headers
        server_info = self._extract_server_info(headers)
        
        if server_info:
            # Add new headers to our set
            before_count = len(self.server_headers)
            self.server_headers.update(server_info)
            after_count = len(self.server_headers)
            
            # If new headers were added, update UI
            if after_count > before_count:
                self._update_headers_display()
                self._update_stats()
                
                # Auto-match if JSON is loaded
                if self.services_data:
                    self._match_services()
    
    def _extract_server_info(self, headers):
        """Extract server and service-related information from headers"""
        server_info = []
        
        # Headers that commonly contain server/service information
        target_headers = [
            'server', 'x-powered-by', 'x-aspnet-version', 'x-generator',
            'x-drupal-cache', 'x-varnish', 'x-cache', 'x-served-by',
            'x-runtime', 'x-frame-options', 'x-content-type-options',
            'x-xss-protection', 'x-pingback', 'link', 'via', 'x-forwarded-server',
            'x-proxy', 'x-load-balancer', 'x-application-context', 'x-version',
            'x-service', 'x-application', 'x-technology', 'x-framework',
            'x-cms', 'x-webserver', 'x-backend', 'x-frontend', 'x-middleware'
        ]
        
        for header in headers:
            header_lower = header.lower()
            
            # Check if this header contains server/service information
            if any(target in header_lower for target in target_headers):
                server_info.append(header)
        
        return server_info
    
    def _update_headers_display(self):
        """Update the headers text area"""
        sorted_headers = sorted(list(self.server_headers))
        self.headers_text.setText("\n".join(sorted_headers))
    
    def _update_stats(self):
        """Update the statistics display"""
        stats_html = "<html>"
        stats_html += "<b>Status:</b> "
        
        if self.services_data:
            stats_html += "<font color='green'>JSON Loaded</font><br>"
        else:
            stats_html += "<font color='red'>No JSON Loaded</font><br>"
        
        stats_html += "<b>Unique Server Headers:</b> {}<br>".format(len(self.server_headers))
        stats_html += "<b>Matched Services:</b> {}<br>".format(len(self.matched_services))
        stats_html += "<b>Generated Endpoints:</b> {}".format(len(self.matched_endpoints))
        stats_html += "</html>"
        
        self.stats_label.setText(stats_html)
    
    def normalize_text(self, text):
        """Normalize text for comparison"""
        return re.sub(r'[^a-zA-Z0-9\s]', '', text.lower())
    
    def extract_service_keywords(self, service_name):
        """Extract meaningful keywords from service names"""
        ignore_words = {'server', 'service', 'http', 'https', 'ssl', 'tls', 'web', 'application', 'api'}
        words = re.findall(r'\b\w+\b', service_name.lower())
        keywords = [word for word in words if len(word) > 2 and word not in ignore_words]
        return keywords
    
    def extract_header_value(self, line):
        """Extract the value portion from header lines"""
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                header_name = parts[0].strip().lower()
                header_value = parts[1].strip()
                return header_name, header_value
        return None, line
    
    def should_match_header_name(self, header_name):
        """Determine if we should match against the header name itself"""
        header_name_indicators = [
            'x-drupal-cache', 'x-varnish', 'x-cache', 'x-served-by',
            'x-pingback', 'x-generator', 'x-powered-by', 'x-aspnet-version',
            'x-runtime', 'x-application-context', 'x-version', 'x-service',
            'x-application', 'x-technology', 'x-framework', 'x-cms',
            'x-webserver', 'x-backend', 'x-frontend', 'x-middleware'
        ]
        
        return any(indicator in header_name for indicator in header_name_indicators)
    
    def _match_services(self):
        """Match detected headers against services JSON"""
        if not self.services_data:
            return
        
        new_endpoints = set()
        new_services = set()
        
        # Process each header
        for header in self.server_headers:
            # Extract header name and value
            header_name, header_value = self.extract_header_value(header)
            
            # Determine what to match against
            if header_name == 'server':
                match_text = header_value
            elif header_name and self.should_match_header_name(header_name):
                match_text = header_name
            else:
                match_text = header
            
            normalized_match_text = self.normalize_text(match_text)
            
            # Check against all services
            for port_info in self.services_data.get('Ports', []):
                for service_info in port_info.get('PotentialServices', []):
                    service_name = service_info.get('Service', '')
                    
                    match_found = False
                    
                    # Strategy 1: Direct substring match
                    if service_name.lower() in match_text.lower():
                        match_found = True
                    
                    # Strategy 2: Keyword matching
                    if not match_found:
                        service_keywords = self.extract_service_keywords(service_name)
                        for keyword in service_keywords:
                            if keyword in normalized_match_text:
                                match_found = True
                                break
                    
                    # Strategy 3: Reverse matching
                    if not match_found:
                        match_words = re.findall(r'\b\w+\b', normalized_match_text)
                        for word in match_words:
                            if len(word) > 2 and word in self.normalize_text(service_name):
                                match_found = True
                                break
                    
                    if match_found:
                        new_services.add(service_name)
                        
                        # Add endpoints
                        common_endpoints = service_info.get('CommonEndpoints', [])
                        new_endpoints.update(common_endpoints)
                        
                        undesirable_endpoints = service_info.get('UndesirableEndpoints', [])
                        new_endpoints.update(undesirable_endpoints)
        
        # Update if we found new matches
        if new_services != self.matched_services or new_endpoints != self.matched_endpoints:
            self.matched_services = new_services
            self.matched_endpoints = new_endpoints
            self._update_endpoints_display()
            self._update_stats()
    
    def _update_endpoints_display(self):
        """Update the endpoints preview"""
        if self.matched_endpoints:
            sorted_endpoints = sorted(list(self.matched_endpoints))
            preview = "\n".join(sorted_endpoints[:100])  # Show first 100
            
            if len(sorted_endpoints) > 100:
                preview += "\n\n... and {} more endpoints".format(len(sorted_endpoints) - 100)
            
            self.endpoints_text.setText(preview)
            self.export_button.setEnabled(True)
        else:
            self.endpoints_text.setText("No endpoints matched yet.\n\nBrowse the target application or click 'Scan History' to detect services.")
            self.export_button.setEnabled(False)
    
    def generate_wordlist(self, event):
        """Generate/refresh the wordlist from current data"""
        if not self.services_data:
            print("No services JSON loaded!")
            return
        
        print("Generating wordlist from {} headers...".format(len(self.server_headers)))
        self._match_services()
        print("Generated {} endpoints from {} services".format(
            len(self.matched_endpoints), 
            len(self.matched_services)
        ))
        
        if self.matched_services:
            print("\nMatched services:")
            for service in sorted(self.matched_services):
                print("  - {}".format(service))
    
    def clear_data(self, event):
        """Clear all collected data"""
        self.server_headers.clear()
        self.matched_services.clear()
        self.matched_endpoints.clear()
        
        self.headers_text.setText("")
        self.endpoints_text.setText("")
        
        self._update_stats()
        print("Cleared all collected data")
    
    def export_wordlist(self, event):
        """Export wordlist to file"""
        if not self.matched_endpoints:
            print("No endpoints to export!")
            return
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Wordlist")
        chooser.setSelectedFile(java.io.File("wordlist.txt"))
        
        ret = chooser.showSaveDialog(self._main_panel)
        
        if ret == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            try:
                sorted_endpoints = sorted(list(self.matched_endpoints))
                
                with open(file_path, 'w') as f:
                    for endpoint in sorted_endpoints:
                        f.write(endpoint + "\n")
                
                print("Wordlist exported to: {}".format(file_path))
                print("Total endpoints: {}".format(len(sorted_endpoints)))
                
            except Exception as e:
                print("Error exporting wordlist: {}".format(str(e)))


# Need to import this for file chooser
import java.io.File
