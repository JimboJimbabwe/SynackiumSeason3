from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, JLabel,
                         BoxLayout, BorderFactory, JButton, JTextArea,
                         JTabbedPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Color, Font, Dimension
from java.lang import Object
import re
import base64
from collections import defaultdict

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("IDOR Pattern Detector")
        
        # Data storage
        self.idor_findings = []  # List of findings with details
        self.finding_index = 0
        
        # Pattern statistics
        self.pattern_stats = defaultdict(int)
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        print("="*70)
        print("IDOR Pattern Detector Loaded")
        print("="*70)
        print("Monitoring traffic for vulnerable ID patterns...")
        print("Patterns detected:")
        print("  - Sequential integers")
        print("  - Base64/Hex encoded IDs")
        print("  - MongoDB ObjectIDs")
        print("  - UUIDs (v1/v4)")
        print("  - High similarity patterns")
        print("  - Timestamp-based IDs")
        print("  - Compound IDs")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI"""
        self._main_panel = JPanel(BorderLayout())
        
        # Top panel - Statistics
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        title = JLabel("<html><b>IDOR Pattern Detector</b> - Real-time vulnerability detection</html>")
        title.setFont(Font("Dialog", Font.BOLD, 14))
        top_panel.add(title)
        
        # Statistics label
        self.stats_label = JLabel("Waiting for traffic...")
        self.stats_label.setFont(Font("Dialog", Font.PLAIN, 12))
        top_panel.add(self.stats_label)
        
        # Clear button
        button_panel = JPanel()
        self.clear_button = JButton("Clear All Findings", actionPerformed=self.clear_findings)
        button_panel.add(self.clear_button)
        top_panel.add(button_panel)
        
        # Main split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Top: Findings table
        table_panel = JPanel(BorderLayout())
        table_panel.setBorder(BorderFactory.createTitledBorder("Detected IDOR Vulnerabilities"))
        
        self.table_model = DefaultTableModel(
            ["Index", "Confidence", "Pattern Type", "URL", "Location", "Example Value"],
            0
        )
        self.findings_table = JTable(self.table_model)
        self.findings_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.findings_table.getColumnModel().getColumn(0).setPreferredWidth(60)   # Index
        self.findings_table.getColumnModel().getColumn(1).setPreferredWidth(80)   # Confidence
        self.findings_table.getColumnModel().getColumn(2).setPreferredWidth(200)  # Pattern
        self.findings_table.getColumnModel().getColumn(3).setPreferredWidth(300)  # URL
        self.findings_table.getColumnModel().getColumn(4).setPreferredWidth(150)  # Location
        self.findings_table.getColumnModel().getColumn(5).setPreferredWidth(200)  # Example
        
        # Custom renderer for confidence column
        self.findings_table.setDefaultRenderer(Object, ConfidenceCellRenderer())
        
        table_scroll = JScrollPane(self.findings_table)
        table_panel.add(table_scroll, BorderLayout.CENTER)
        
        # Bottom: Details panel with tabs
        details_panel = JPanel(BorderLayout())
        details_panel.setBorder(BorderFactory.createTitledBorder("Finding Details"))
        
        self.details_tabs = JTabbedPane()
        
        # Tab 1: Exploitation guide
        self.exploit_text = JTextArea()
        self.exploit_text.setEditable(False)
        self.exploit_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.exploit_text.setLineWrap(True)
        self.exploit_text.setWrapStyleWord(True)
        exploit_scroll = JScrollPane(self.exploit_text)
        self.details_tabs.addTab("Exploitation", exploit_scroll)
        
        # Tab 2: Generated test values
        self.testvals_text = JTextArea()
        self.testvals_text.setEditable(False)
        self.testvals_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        testvals_scroll = JScrollPane(self.testvals_text)
        self.details_tabs.addTab("Generated Test Values", testvals_scroll)
        
        # Tab 3: Technical details
        self.technical_text = JTextArea()
        self.technical_text.setEditable(False)
        self.technical_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        technical_scroll = JScrollPane(self.technical_text)
        self.details_tabs.addTab("Technical Details", technical_scroll)
        
        details_panel.add(self.details_tabs, BorderLayout.CENTER)
        
        # Add table selection listener
        from javax.swing.event import ListSelectionListener
        
        class TableSelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    self.extender.on_table_selection()
        
        self.findings_table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self)
        )
        
        # Assemble split pane
        split_pane.setTopComponent(table_panel)
        split_pane.setBottomComponent(details_panel)
        split_pane.setDividerLocation(300)
        
        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(split_pane, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "IDOR Detector"
    
    def getUiComponent(self):
        return self._main_panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process each HTTP message"""
        if messageIsRequest:
            return
        
        # Get request and response
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        
        if not response:
            return
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        response_info = self._helpers.analyzeResponse(response)
        
        url = str(request_info.getUrl())
        
        # Scan URL parameters
        self._scan_url_parameters(messageInfo, url)
        
        # Scan request body
        self._scan_request_body(messageInfo, url)
        
        # Scan response body
        self._scan_response_body(messageInfo, url, response)
        
        # Scan headers
        self._scan_headers(messageInfo, url, request_info, response_info)
    
    def _scan_url_parameters(self, messageInfo, url):
        """Scan URL parameters for IDOR patterns"""
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        for param in request_info.getParameters():
            if param.getType() == 0:  # URL parameter
                param_name = param.getName()
                param_value = param.getValue()
                
                if param_value:
                    patterns = self._detect_patterns(param_value)
                    
                    for pattern in patterns:
                        self._add_finding(
                            url=url,
                            location="URL Parameter: {}".format(param_name),
                            pattern_type=pattern['type'],
                            confidence=pattern['confidence'],
                            example_value=param_value,
                            description=pattern['description'],
                            exploitation=pattern['exploitation'],
                            generator_hint=pattern.get('generator_hint'),
                            messageInfo=messageInfo
                        )
    
    def _scan_request_body(self, messageInfo, url):
        """Scan request body for IDOR patterns"""
        request = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Get body parameters
        for param in request_info.getParameters():
            if param.getType() == 1:  # Body parameter
                param_name = param.getName()
                param_value = param.getValue()
                
                if param_value:
                    patterns = self._detect_patterns(param_value)
                    
                    for pattern in patterns:
                        self._add_finding(
                            url=url,
                            location="Request Body Parameter: {}".format(param_name),
                            pattern_type=pattern['type'],
                            confidence=pattern['confidence'],
                            example_value=param_value,
                            description=pattern['description'],
                            exploitation=pattern['exploitation'],
                            generator_hint=pattern.get('generator_hint'),
                            messageInfo=messageInfo
                        )
        
        # Also scan raw body for JSON/XML IDs
        body_offset = request_info.getBodyOffset()
        if body_offset < len(request):
            body = request[body_offset:].tostring()
            self._scan_text_for_ids(body, url, "Request Body", messageInfo)
    
    def _scan_response_body(self, messageInfo, url, response):
        """Scan response body for IDOR patterns"""
        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        
        if body_offset < len(response):
            body = response[body_offset:].tostring()
            self._scan_text_for_ids(body, url, "Response Body", messageInfo)
    
    def _scan_headers(self, messageInfo, url, request_info, response_info):
        """Scan headers for IDOR patterns"""
        # Scan request headers
        for header in request_info.getHeaders():
            if ':' in header:
                parts = header.split(':', 1)
                if len(parts) == 2:
                    header_name = parts[0].strip()
                    header_value = parts[1].strip()
                    
                    patterns = self._detect_patterns(header_value)
                    
                    for pattern in patterns:
                        self._add_finding(
                            url=url,
                            location="Request Header: {}".format(header_name),
                            pattern_type=pattern['type'],
                            confidence=pattern['confidence'],
                            example_value=header_value,
                            description=pattern['description'],
                            exploitation=pattern['exploitation'],
                            generator_hint=pattern.get('generator_hint'),
                            messageInfo=messageInfo
                        )
        
        # Scan response headers
        for header in response_info.getHeaders():
            if ':' in header:
                parts = header.split(':', 1)
                if len(parts) == 2:
                    header_name = parts[0].strip()
                    header_value = parts[1].strip()
                    
                    patterns = self._detect_patterns(header_value)
                    
                    for pattern in patterns:
                        self._add_finding(
                            url=url,
                            location="Response Header: {}".format(header_name),
                            pattern_type=pattern['type'],
                            confidence=pattern['confidence'],
                            example_value=header_value,
                            description=pattern['description'],
                            exploitation=pattern['exploitation'],
                            generator_hint=pattern.get('generator_hint'),
                            messageInfo=messageInfo
                        )
    
    def _scan_text_for_ids(self, text, url, location_prefix, messageInfo):
        """Scan arbitrary text for ID-like patterns"""
        # Look for common ID patterns in JSON/XML
        # Match quoted strings that look like IDs
        id_patterns = [
            r'"id"\s*:\s*"([^"]+)"',
            r'"_id"\s*:\s*"([^"]+)"',
            r'"userId"\s*:\s*"([^"]+)"',
            r'"orderId"\s*:\s*"([^"]+)"',
            r'<id>([^<]+)</id>',
            r'<userId>([^<]+)</userId>',
        ]
        
        for pattern in id_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            
            for match in matches:
                id_value = match.group(1)
                
                patterns = self._detect_patterns(id_value)
                
                for pat in patterns:
                    self._add_finding(
                        url=url,
                        location="{} (field: {})".format(location_prefix, match.group(0)[:30]),
                        pattern_type=pat['type'],
                        confidence=pat['confidence'],
                        example_value=id_value,
                        description=pat['description'],
                        exploitation=pat['exploitation'],
                        generator_hint=pat.get('generator_hint'),
                        messageInfo=messageInfo
                    )
    
    def _detect_patterns(self, value):
        """Detect IDOR patterns in a value"""
        if not value or len(value) < 2:
            return []
        
        patterns = []
        
        # Sequential integer
        if value.isdigit() and 2 <= len(value) <= 10:
            patterns.append({
                'type': 'Sequential Integer',
                'confidence': 'HIGH',
                'description': 'Numeric ID that can be enumerated',
                'exploitation': 'Increment/decrement the integer value',
                'generator_hint': ('sequential_int', int(value))
            })
        
        # Base64 encoded
        b64_result = self._try_base64_decode(value)
        if b64_result:
            patterns.append({
                'type': 'Base64 Encoded Integer',
                'confidence': 'HIGH',
                'description': 'Base64 decodes to: {}'.format(b64_result),
                'exploitation': 'Decode, increment, re-encode',
                'generator_hint': ('base64_int', b64_result)
            })
        
        # Hex encoded
        hex_result = self._try_hex_decode(value)
        if hex_result:
            patterns.append({
                'type': 'Hex Encoded Integer',
                'confidence': 'HIGH',
                'description': 'Hex decodes to: {}'.format(hex_result),
                'exploitation': 'Convert to decimal, increment, convert back',
                'generator_hint': ('hex_int', hex_result)
            })
        
        # MongoDB ObjectID
        if len(value) == 24 and re.match(r'^[0-9a-fA-F]{24}$', value):
            timestamp_hex = value[:8]
            counter_hex = value[-6:]
            patterns.append({
                'type': 'MongoDB ObjectID',
                'confidence': 'HIGH',
                'description': 'Timestamp: {}, Counter: {}'.format(timestamp_hex, counter_hex),
                'exploitation': 'Keep timestamp, enumerate counter (last 6 chars)',
                'generator_hint': ('mongodb_objectid', timestamp_hex, int(counter_hex, 16))
            })
        
        # UUID
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        if re.match(uuid_pattern, value):
            version = value[14]
            
            if version == '1':
                patterns.append({
                    'type': 'UUIDv1 (Time-based)',
                    'confidence': 'MEDIUM',
                    'description': 'Time-based UUID - partially predictable',
                    'exploitation': 'Extract timestamp, generate nearby UUIDs',
                    'generator_hint': ('uuidv1', value)
                })
            elif version == '4':
                patterns.append({
                    'type': 'UUIDv4 (Random)',
                    'confidence': 'LOW',
                    'description': 'Cryptographically random - likely secure',
                    'exploitation': 'Not typically vulnerable',
                    'generator_hint': None
                })
        
        # Unix timestamp
        if value.isdigit() and len(value) == 10:
            patterns.append({
                'type': 'Unix Timestamp (seconds)',
                'confidence': 'HIGH',
                'description': 'Epoch timestamp in seconds',
                'exploitation': 'Enumerate timestamps before/after',
                'generator_hint': ('unix_timestamp', int(value))
            })
        
        if value.isdigit() and len(value) == 13:
            patterns.append({
                'type': 'Unix Timestamp (milliseconds)',
                'confidence': 'HIGH',
                'description': 'Epoch timestamp in milliseconds',
                'exploitation': 'Enumerate timestamps before/after',
                'generator_hint': ('unix_timestamp_ms', int(value))
            })
        
        # Compound ID with separators
        for sep in ['-', '_', '.']:
            if sep in value:
                parts = value.split(sep)
                numeric_parts = [(i, p) for i, p in enumerate(parts) if p.isdigit()]
                
                if numeric_parts:
                    patterns.append({
                        'type': 'Compound ID',
                        'confidence': 'HIGH',
                        'description': 'Multiple parts separated by "{}"'.format(sep),
                        'exploitation': 'Enumerate numeric parts: {}'.format([p for i,p in numeric_parts]),
                        'generator_hint': ('compound_id', parts, sep, numeric_parts)
                    })
                    break
        
        return patterns
    
    def _try_base64_decode(self, s):
        """Try to decode base64"""
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s) or len(s) < 4:
            return None
        
        try:
            decoded = base64.b64decode(s)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            
            if decoded_str.isdigit():
                return decoded_str
            
            if decoded_str.isalnum() and 2 < len(decoded_str) < 50:
                return decoded_str
        except:
            pass
        
        return None
    
    def _try_hex_decode(self, s):
        """Try to decode hex"""
        clean = s.replace('0x', '').replace('0X', '')
        
        if not re.match(r'^[0-9a-fA-F]+$', clean) or len(clean) < 2 or len(clean) > 16:
            return None
        
        try:
            value = int(clean, 16)
            if 0 < value < 10**15:
                return value
        except:
            pass
        
        return None
    
    def _add_finding(self, url, location, pattern_type, confidence, example_value,
                     description, exploitation, generator_hint, messageInfo):
        """Add a finding to the table"""
        # Check for duplicates (same pattern type + location + value)
        for finding in self.idor_findings:
            if (finding['pattern_type'] == pattern_type and
                finding['location'] == location and
                finding['example_value'] == example_value):
                return  # Already found this
        
        # Create finding
        finding = {
            'index': self.finding_index,
            'url': url,
            'location': location,
            'pattern_type': pattern_type,
            'confidence': confidence,
            'example_value': example_value,
            'description': description,
            'exploitation': exploitation,
            'generator_hint': generator_hint,
            'messageInfo': messageInfo
        }
        
        self.idor_findings.append(finding)
        self.finding_index += 1
        
        # Update pattern stats
        self.pattern_stats[pattern_type] += 1
        
        # Add to table
        url_short = url[:50] + "..." if len(url) > 50 else url
        value_short = example_value[:30] + "..." if len(example_value) > 30 else example_value
        
        self.table_model.addRow([
            str(finding['index']),
            confidence,
            pattern_type,
            url_short,
            location,
            value_short
        ])
        
        # Update statistics
        self._update_statistics()
        
        # Print to console
        print("[IDOR] {} - {} at {} - Value: {}".format(
            confidence,
            pattern_type,
            location,
            example_value[:50]
        ))
    
    def _update_statistics(self):
        """Update statistics label"""
        total = len(self.idor_findings)
        high_conf = sum(1 for f in self.idor_findings if f['confidence'] == 'HIGH')
        
        stats_html = "<html>"
        stats_html += "<b>Total Findings:</b> {} ({} HIGH confidence)<br>".format(total, high_conf)
        stats_html += "<b>Pattern Breakdown:</b> "
        
        pattern_items = []
        for pattern_type, count in sorted(self.pattern_stats.items(), key=lambda x: x[1], reverse=True):
            pattern_items.append("{} ({})".format(pattern_type, count))
        
        stats_html += ", ".join(pattern_items[:5])
        if len(pattern_items) > 5:
            stats_html += "..."
        
        stats_html += "</html>"
        
        self.stats_label.setText(stats_html)
    
    def on_table_selection(self):
        """Handle table row selection"""
        selected_row = self.findings_table.getSelectedRow()
        
        if selected_row < 0 or selected_row >= len(self.idor_findings):
            return
        
        finding = self.idor_findings[selected_row]
        
        # Populate exploitation tab
        exploit_text = []
        exploit_text.append("="*60)
        exploit_text.append("EXPLOITATION GUIDE")
        exploit_text.append("="*60)
        exploit_text.append("")
        exploit_text.append("Pattern Type: {}".format(finding['pattern_type']))
        exploit_text.append("Confidence: {}".format(finding['confidence']))
        exploit_text.append("Location: {}".format(finding['location']))
        exploit_text.append("Example Value: {}".format(finding['example_value']))
        exploit_text.append("")
        exploit_text.append("Description:")
        exploit_text.append("  {}".format(finding['description']))
        exploit_text.append("")
        exploit_text.append("How to Exploit:")
        exploit_text.append("  {}".format(finding['exploitation']))
        exploit_text.append("")
        exploit_text.append("Steps:")
        exploit_text.append("  1. Use the generated test values in the 'Generated Test Values' tab")
        exploit_text.append("  2. Send the request to Intruder")
        exploit_text.append("  3. Mark the ID position as payload position")
        exploit_text.append("  4. Load the test values as payload")
        exploit_text.append("  5. Look for responses with different content length or status codes")
        exploit_text.append("")
        exploit_text.append("URL: {}".format(finding['url']))
        
        self.exploit_text.setText("\n".join(exploit_text))
        
        # Generate test values
        if finding['generator_hint']:
            test_values = self._generate_test_values(finding['generator_hint'], 50)
            
            testvals_text = []
            testvals_text.append("Generated {} test values for pattern: {}".format(
                len(test_values),
                finding['pattern_type']
            ))
            testvals_text.append("")
            testvals_text.append("Copy these values and use with Burp Intruder:")
            testvals_text.append("-"*60)
            testvals_text.extend(test_values)
            
            self.testvals_text.setText("\n".join(testvals_text))
        else:
            self.testvals_text.setText("No test value generator available for this pattern type.")
        
        # Technical details
        tech_text = []
        tech_text.append("TECHNICAL DETAILS")
        tech_text.append("="*60)
        tech_text.append("")
        tech_text.append("Finding Index: {}".format(finding['index']))
        tech_text.append("URL: {}".format(finding['url']))
        tech_text.append("Location: {}".format(finding['location']))
        tech_text.append("Pattern Type: {}".format(finding['pattern_type']))
        tech_text.append("Confidence Level: {}".format(finding['confidence']))
        tech_text.append("Example Value: {}".format(finding['example_value']))
        tech_text.append("Value Length: {}".format(len(finding['example_value'])))
        tech_text.append("")
        tech_text.append("Generator Hint: {}".format(finding['generator_hint']))
        tech_text.append("")
        tech_text.append("To send this request to Repeater/Intruder:")
        tech_text.append("  1. Find the request in HTTP History")
        tech_text.append("  2. Right-click and send to desired tool")
        tech_text.append("  3. Use the generated test values from the other tab")
        
        self.technical_text.setText("\n".join(tech_text))
    
    def _generate_test_values(self, hint, count):
        """Generate test values based on hint"""
        if not hint:
            return []
        
        pattern_type = hint[0]
        values = []
        
        try:
            if pattern_type == 'sequential_int':
                base_val = hint[1]
                for i in range(-10, count):
                    new_val = base_val + i
                    if new_val >= 0:
                        values.append(str(new_val))
            
            elif pattern_type == 'base64_int':
                base_num = hint[1]
                if isinstance(base_num, str) and base_num.isdigit():
                    base_num = int(base_num)
                
                for i in range(-10, count):
                    new_val = base_num + i
                    if new_val >= 0:
                        encoded = base64.b64encode(str(new_val).encode()).decode()
                        values.append(encoded)
            
            elif pattern_type == 'hex_int':
                base_num = hint[1]
                for i in range(-10, count):
                    new_val = base_num + i
                    if new_val >= 0:
                        values.append(hex(new_val))
            
            elif pattern_type == 'mongodb_objectid':
                timestamp_hex = hint[1]
                base_counter = hint[2]
                
                for i in range(count):
                    new_counter = base_counter + i
                    counter_hex = format(new_counter, 'x').zfill(6)
                    middle = '0' * 10
                    values.append(timestamp_hex + middle + counter_hex)
            
            elif pattern_type == 'unix_timestamp':
                base_time = hint[1]
                for i in range(-3600, 3600, 60):
                    values.append(str(base_time + i))
            
            elif pattern_type == 'compound_id':
                parts = hint[1]
                sep = hint[2]
                numeric_parts = hint[3]
                
                if numeric_parts:
                    pos, num_str = numeric_parts[0]
                    base_num = int(num_str)
                    
                    for i in range(count):
                        new_parts = list(parts)
                        new_parts[pos] = str(base_num + i)
                        values.append(sep.join(new_parts))
        
        except Exception as e:
            print("Error generating test values: {}".format(str(e)))
        
        return values
    
    def clear_findings(self, event):
        """Clear all findings"""
        self.idor_findings = []
        self.finding_index = 0
        self.pattern_stats.clear()
        
        self.table_model.setRowCount(0)
        self.exploit_text.setText("")
        self.testvals_text.setText("")
        self.technical_text.setText("")
        
        self._update_statistics()
        
        print("Cleared all IDOR findings")


class ConfidenceCellRenderer(DefaultTableCellRenderer):
    """Custom renderer for confidence column"""
    
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        
        if column == 1:  # Confidence column
            if value == "HIGH":
                component.setBackground(Color(255, 200, 200))  # Light red
            elif value == "MEDIUM":
                component.setBackground(Color(255, 255, 200))  # Light yellow
            elif value == "LOW":
                component.setBackground(Color(220, 220, 220))  # Light gray
            else:
                component.setBackground(Color.WHITE)
        else:
            if not isSelected:
                component.setBackground(Color.WHITE)
        
        return component
