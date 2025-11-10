from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JButton, JScrollPane, JTextArea, 
                         BoxLayout, BorderFactory, JLabel, JSplitPane)
from java.awt import BorderLayout, GridLayout, Dimension
from java.awt.event import ActionListener
import re
import json

class BurpExtender(IBurpExtender, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Manual Exploit Searcher")
        
        # Data storage
        self.detected_software = []  # List of detected software
        self.current_messageInfo = None
        
        # Create UI
        self._create_ui()
        
        # Add tab
        callbacks.addSuiteTab(self)
        
        print("Manual Exploit Searcher loaded!")
        print("Select a request in HTTP History and click 'Load Selected Request'")
    
    def _create_ui(self):
        """Create the UI"""
        self._main_panel = JPanel(BorderLayout())
        
        # Top panel - Controls
        top_panel = JPanel(GridLayout(1, 2, 10, 10))
        top_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        self.load_button = JButton("Load Selected Request", actionPerformed=self.load_selected_request)
        self.clear_button = JButton("Clear", actionPerformed=self.clear_data)
        
        top_panel.add(self.load_button)
        top_panel.add(self.clear_button)
        
        # Middle panel - Detected software
        middle_panel = JPanel(BorderLayout())
        middle_panel.setBorder(BorderFactory.createTitledBorder("Detected Software"))
        
        self.software_text = JTextArea()
        self.software_text.setEditable(False)
        self.software_text.setText("No request loaded.\n\nSelect a request in HTTP History and click 'Load Selected Request'")
        software_scroll = JScrollPane(self.software_text)
        
        middle_panel.add(software_scroll, BorderLayout.CENTER)
        
        # Bottom panel - Search controls and results
        bottom_panel = JPanel(BorderLayout())
        
        # Search button
        search_panel = JPanel()
        self.search_button = JButton("Search All on Exploit-DB", actionPerformed=self.search_all_exploits)
        self.search_button.setEnabled(False)
        search_panel.add(self.search_button)
        
        # Results area
        results_panel = JPanel(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("Search Results"))
        
        self.results_text = JTextArea()
        self.results_text.setEditable(False)
        self.results_text.setText("Search results will appear here...")
        results_scroll = JScrollPane(self.results_text)
        
        results_panel.add(results_scroll, BorderLayout.CENTER)
        
        bottom_panel.add(search_panel, BorderLayout.NORTH)
        bottom_panel.add(results_panel, BorderLayout.CENTER)
        
        # Add all panels
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setTopComponent(middle_panel)
        split_pane.setBottomComponent(bottom_panel)
        split_pane.setDividerLocation(200)
        
        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(split_pane, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "Exploit Search"
    
    def getUiComponent(self):
        return self._main_panel
    
    def load_selected_request(self, event):
        """Load currently selected request from Burp"""
        print("\n" + "="*70)
        print("LOADING SELECTED REQUEST")
        print("="*70)
        
        # Get selected messages
        selected_messages = self._callbacks.getSelectedMessages()
        
        if not selected_messages or len(selected_messages) == 0:
            print("ERROR: No request selected!")
            self.software_text.setText("ERROR: No request selected!\n\nPlease select a request in:\n- HTTP History\n- Proxy History\n- Repeater\n- Any other tool")
            return
        
        # Get first selected message
        self.current_messageInfo = selected_messages[0]
        
        # Get response
        response = self.current_messageInfo.getResponse()
        if not response:
            print("ERROR: Selected request has no response!")
            self.software_text.setText("ERROR: Selected request has no response!\n\nPlease select a request that has been sent and received a response.")
            return
        
        # Extract headers
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        # Get URL for display
        request_info = self._helpers.analyzeRequest(self.current_messageInfo)
        url = str(request_info.getUrl())
        
        print("URL: {}".format(url))
        print("Extracting software versions from {} headers...".format(len(headers)))
        
        # Extract software
        self.detected_software = self._extract_all_software(headers)
        
        print("Detected {} software versions".format(len(self.detected_software)))
        
        # Display results
        display_text = "Request URL: {}\n\n".format(url)
        display_text += "="*60 + "\n"
        display_text += "DETECTED SOFTWARE:\n"
        display_text += "="*60 + "\n\n"
        
        if self.detected_software:
            for i, software in enumerate(self.detected_software, 1):
                display_text += "{}. {}\n".format(i, software)
                display_text += "   Source: {}\n\n".format(software.get('source', 'Unknown'))
            
            self.search_button.setEnabled(True)
        else:
            display_text += "No software versions detected.\n\n"
            display_text += "The response headers did not contain recognizable software version information."
            self.search_button.setEnabled(False)
        
        self.software_text.setText(display_text)
        self.results_text.setText("Click 'Search All on Exploit-DB' to search for exploits...")
        
        print("="*70 + "\n")
    
    def _extract_all_software(self, headers):
        """Extract all software versions from headers"""
        software_list = []
        
        # Headers that commonly contain version info
        target_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
        
        for header in headers:
            header_lower = header.lower()
            
            # Check if this is a target header
            for target in target_headers:
                if header_lower.startswith(target + ':'):
                    # Extract the value
                    parts = header.split(':', 1)
                    if len(parts) == 2:
                        header_value = parts[1].strip()
                        
                        # Extract version info
                        versions = self._extract_version_info(header_value)
                        
                        for version in versions:
                            software_list.append({
                                'query': version,
                                'source': header,
                                'header_name': parts[0]
                            })
        
        return software_list
    
    def _extract_version_info(self, header_value):
        """Extract version information from header value"""
        version_patterns = [
            r'(\w+)[/\s]+([\d]+\.[\d]+\.?[\d]*)',
            r'(\w+)[/\s]+([v]?[\d]+\.[\d]+\.?[\d]*)',
            r'([\w\-]+)[/\s]+([\d\.]+)',
        ]
        
        extracted = []
        
        for pattern in version_patterns:
            matches = re.finditer(pattern, header_value, re.IGNORECASE)
            for match in matches:
                product = match.group(1)
                version = match.group(2)
                if len(product) > 1 and len(version) > 1:
                    extracted.append("{} {}".format(product, version))
        
        # If no version found, return the whole value if it looks valid
        if not extracted:
            if re.search(r'[a-zA-Z]{2,}', header_value) and len(header_value) < 50:
                extracted.append(header_value)
        
        return extracted
    
    def search_all_exploits(self, event):
        """Search Exploit-DB for all detected software"""
        if not self.detected_software:
            print("No software to search!")
            return
        
        self.results_text.setText("Searching Exploit-DB...\n\n")
        self.search_button.setEnabled(False)
        
        # Search in background thread
        from threading import Thread
        
        def search_task():
            results_text = ""
            
            for i, software in enumerate(self.detected_software, 1):
                query = software['query']
                source = software['source']
                
                results_text += "="*70 + "\n"
                results_text += "SEARCH {}/{}: {}\n".format(i, len(self.detected_software), query)
                results_text += "Source: {}\n".format(source)
                results_text += "="*70 + "\n\n"
                
                print("Searching for: {}".format(query))
                
                # Search Exploit-DB
                exploits = self._search_exploitdb(query, limit=10)
                
                if exploits:
                    results_text += "Found {} exploit(s):\n\n".format(len(exploits))
                    
                    for exploit in exploits:
                        exploit_id = exploit.get("id", "Unknown")
                        description = exploit.get("description", ["", "Unknown"])
                        title = description[1] if len(description) > 1 else "Unknown"
                        date = exploit.get("date_published", "Unknown")
                        
                        results_text += "  [{}] {}\n".format(exploit_id, title)
                        results_text += "  Date: {}\n".format(date)
                        results_text += "  URL: https://www.exploit-db.com/exploits/{}\n\n".format(exploit_id)
                    
                    print("  Found {} exploits".format(len(exploits)))
                else:
                    results_text += "No exploits found.\n\n"
                    print("  No exploits found")
                
                results_text += "\n"
            
            # Update UI (must be done on Swing thread)
            from javax.swing import SwingUtilities
            SwingUtilities.invokeLater(lambda: self._update_results(results_text))
        
        thread = Thread(target=search_task)
        thread.daemon = True
        thread.start()
    
    def _update_results(self, text):
        """Update results text (called from Swing thread)"""
        self.results_text.setText(text)
        self.search_button.setEnabled(True)
    
    def _search_exploitdb(self, query, limit=10):
        """Search Exploit-DB using your exact API call"""
        import urllib
        
        try:
            # Build URL with parameters (using your exact params)
            base_url = "https://www.exploit-db.com/search"
            
            params = {
                "q": query,
                "draw": "1",
                "columns[0][data]": "date_published",
                "columns[0][name]": "date_published",
                "columns[0][searchable]": "true",
                "columns[0][orderable]": "true",
                "columns[0][search][value]": "",
                "columns[0][search][regex]": "false",
                "columns[1][data]": "download",
                "columns[1][name]": "download",
                "columns[1][searchable]": "false",
                "columns[1][orderable]": "false",
                "columns[1][search][value]": "",
                "columns[1][search][regex]": "false",
                "columns[2][data]": "application_md5",
                "columns[2][name]": "application_md5",
                "columns[2][searchable]": "true",
                "columns[2][orderable]": "false",
                "columns[2][search][value]": "",
                "columns[2][search][regex]": "false",
                "columns[3][data]": "verified",
                "columns[3][name]": "verified",
                "columns[3][searchable]": "true",
                "columns[3][orderable]": "false",
                "columns[3][search][value]": "",
                "columns[3][search][regex]": "false",
                "columns[4][data]": "description",
                "columns[4][name]": "description",
                "columns[4][searchable]": "true",
                "columns[4][orderable]": "false",
                "columns[4][search][value]": "",
                "columns[4][search][regex]": "false",
                "columns[5][data]": "type_id",
                "columns[5][name]": "type_id",
                "columns[5][searchable]": "true",
                "columns[5][orderable]": "false",
                "columns[5][search][value]": "",
                "columns[5][search][regex]": "false",
                "columns[6][data]": "platform_id",
                "columns[6][name]": "platform_id",
                "columns[6][searchable]": "true",
                "columns[6][orderable]": "false",
                "columns[6][search][value]": "",
                "columns[6][search][regex]": "false",
                "columns[7][data]": "author_id",
                "columns[7][name]": "author_id",
                "columns[7][searchable]": "false",
                "columns[7][orderable]": "false",
                "columns[7][search][value]": "",
                "columns[7][search][regex]": "false",
                "order[0][column]": "0",
                "order[0][dir]": "desc",
                "start": "0",
                "length": str(limit),
                "search[value]": "",
                "search[regex]": "false"
            }
            
            # Encode parameters
            param_string = urllib.urlencode(params)
            full_url = "{}?{}".format(base_url, param_string)
            
            # Make HTTP request using Burp's helper
            from java.net import URL
            url_obj = URL(full_url)
            
            # Build HTTP request
            request_str = "GET {} HTTP/1.1\r\n".format(url_obj.getPath() + "?" + url_obj.getQuery())
            request_str += "Host: {}\r\n".format(url_obj.getHost())
            request_str += "Accept: application/json\r\n"
            request_str += "X-Requested-With: XMLHttpRequest\r\n"
            request_str += "Referer: https://www.exploit-db.com/search\r\n"
            request_str += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            request_str += "Connection: close\r\n\r\n"
            
            request_bytes = bytearray(request_str)
            
            # Make the request
            response = self._callbacks.makeHttpRequest(
                url_obj.getHost(),
                443,  # HTTPS port
                True,  # Use HTTPS
                request_bytes
            )
            
            # Parse response
            response_str = response.tostring()
            
            # Find JSON body (after headers)
            body_start = response_str.find("\r\n\r\n")
            if body_start == -1:
                body_start = response_str.find("\n\n")
            
            if body_start != -1:
                json_body = response_str[body_start:].strip()
                
                # Parse JSON
                data = json.loads(json_body)
                return data.get("data", [])
            
            return []
            
        except Exception as e:
            print("Error searching Exploit-DB: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            return []
    
    def clear_data(self, event):
        """Clear all data"""
        self.detected_software = []
        self.current_messageInfo = None
        self.software_text.setText("No request loaded.\n\nSelect a request and click 'Load Selected Request'")
        self.results_text.setText("Search results will appear here...")
        self.search_button.setEnabled(False)
        print("Cleared all data")


import urllib
