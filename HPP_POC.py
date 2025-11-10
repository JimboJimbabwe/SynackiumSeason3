from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, 
                         JLabel, BoxLayout, BorderFactory, JButton,
                         JTextArea, JMenuItem, SwingUtilities)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Color, Font, Dimension
from java.awt.event import MouseAdapter
from java.lang import Object
from java.util import ArrayList
from urllib import quote, unquote
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("HPP Payload Generator")
        
        # Data storage
        self.requests_with_params = []
        self.selected_request = None
        self.current_request = None
        self.current_response = None
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        print("="*70)
        print("HTTP Parameter Pollution (HPP) Payload Generator loaded!")
        print("="*70)
        print("Features:")
        print("  - Automatic detection of requests with parameters")
        print("  - Parameter extraction from URL, body, and cookies")
        print("  - Right-click context menu: 'Send to HPP Generator'")
        print("  - Click any request to generate HPP test payloads")
        print("  - Comprehensive payload variations for security testing")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI panel"""
        self._main_panel = JPanel(BorderLayout())
        
        # Create main split pane (horizontal)
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        main_split.setResizeWeight(0.4)  # Give left side 40% of space
        
        # LEFT SIDE: Request list and statistics
        left_panel = JPanel(BorderLayout())
        
        # Statistics panel at top
        stats_panel = JPanel()
        stats_panel.setLayout(BoxLayout(stats_panel, BoxLayout.Y_AXIS))
        stats_panel.setBorder(BorderFactory.createTitledBorder("HPP Detection Statistics"))
        stats_panel.setPreferredSize(Dimension(400, 120))
        
        self.stats_label = JLabel("<html><b>Waiting for requests with parameters...</b><br><br>" +
                                 "Right-click any request in Proxy/Target and select<br>" +
                                 "'Send to HPP Generator' to manually add requests</html>")
        stats_panel.add(self.stats_label)
        
        left_panel.add(stats_panel, BorderLayout.NORTH)
        
        # Request table
        table_panel = JPanel(BorderLayout())
        table_panel.setBorder(BorderFactory.createTitledBorder("Requests with Parameters"))
        
        column_names = ["#", "Method", "URL", "Param Count", "Param Types", "Parameters"]
        self.table_model = DefaultTableModel(column_names, 0)
        self.request_table = JTable(self.table_model)
        
        # Set column widths
        self.request_table.getColumnModel().getColumn(0).setPreferredWidth(30)
        self.request_table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self.request_table.getColumnModel().getColumn(2).setPreferredWidth(200)
        self.request_table.getColumnModel().getColumn(3).setPreferredWidth(60)
        self.request_table.getColumnModel().getColumn(4).setPreferredWidth(80)
        self.request_table.getColumnModel().getColumn(5).setPreferredWidth(150)
        
        # Add mouse listener for row selection
        self.request_table.addMouseListener(TableMouseListener(self))
        
        scroll_pane = JScrollPane(self.request_table)
        table_panel.add(scroll_pane, BorderLayout.CENTER)
        
        left_panel.add(table_panel, BorderLayout.CENTER)
        
        # RIGHT SIDE: HPP Payload Generator
        right_panel = JPanel(BorderLayout())
        right_panel.setBorder(BorderFactory.createTitledBorder("HPP Test Payloads"))
        right_panel.setPreferredSize(Dimension(600, 600))
        
        # Info label
        self.payload_info_label = JLabel("<html><b>Click on a request in the table to generate HPP payloads</b></html>")
        right_panel.add(self.payload_info_label, BorderLayout.NORTH)
        
        # Text area for payloads
        self.payload_text_area = JTextArea()
        self.payload_text_area.setEditable(True)
        self.payload_text_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.payload_text_area.setLineWrap(False)
        self.payload_text_area.setText("Waiting for request selection...\n\n" +
                                       "HOW TO USE:\n" +
                                       "1. Browse normally with Burp Proxy active\n" +
                                       "2. Requests with parameters will appear in the left table\n" +
                                       "3. OR right-click any request and select 'Send to HPP Generator'\n" +
                                       "4. Click a request in the table to generate HPP payloads\n" +
                                       "5. Copy payloads and test in Repeater/Intruder\n")
        
        payload_scroll = JScrollPane(self.payload_text_area)
        right_panel.add(payload_scroll, BorderLayout.CENTER)
        
        # Button panel
        button_panel = JPanel()
        
        self.copy_button = JButton("Copy All Payloads")
        self.copy_button.addActionListener(CopyButtonListener(self))
        button_panel.add(self.copy_button)
        
        self.send_to_repeater_button = JButton("Send Original to Repeater")
        self.send_to_repeater_button.addActionListener(SendToRepeaterListener(self))
        button_panel.add(self.send_to_repeater_button)
        
        self.send_to_intruder_button = JButton("Send to Intruder")
        self.send_to_intruder_button.addActionListener(SendToIntruderListener(self))
        button_panel.add(self.send_to_intruder_button)
        
        self.clear_button = JButton("Clear All Requests")
        self.clear_button.addActionListener(ClearButtonListener(self))
        button_panel.add(self.clear_button)
        
        right_panel.add(button_panel, BorderLayout.SOUTH)
        
        # Add to main split pane
        main_split.setLeftComponent(left_panel)
        main_split.setRightComponent(right_panel)
        main_split.setDividerLocation(500)
        
        self._main_panel.add(main_split, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "HPP Generator"
    
    def getUiComponent(self):
        return self._main_panel
    
    def createMenuItems(self, invocation):
        """Create context menu item"""
        menu_list = ArrayList()
        
        # Only show menu item for requests
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE
        ]:
            menu_item = JMenuItem("Send to HPP Generator")
            menu_item.addActionListener(ContextMenuListener(self, invocation))
            menu_list.add(menu_item)
        
        return menu_list
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process each HTTP message to detect parameters"""
        # Only process responses (so we have both request and response)
        if messageIsRequest:
            return
        
        try:
            self._add_request_if_has_params(messageInfo)
        except Exception as e:
            print("Error processing HTTP message: {}".format(str(e)))
    
    def add_request_from_context_menu(self, messageInfo):
        """Add a request manually from context menu"""
        try:
            self._add_request_if_has_params(messageInfo, force=True)
        except Exception as e:
            print("Error adding request from context menu: {}".format(str(e)))
    
    def _add_request_if_has_params(self, messageInfo, force=False):
        """Add request to table if it has parameters"""
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Extract all parameters
        url_params, body_params, cookie_params = self._extract_all_parameters(messageInfo, request_info)
        
        # Only process if there are parameters (or forced from context menu)
        total_params = len(url_params) + len(body_params) + len(cookie_params)
        if total_params == 0 and not force:
            return
        
        # Get request details
        url = str(request_info.getUrl())
        method = request_info.getMethod()
        
        # Check for duplicates
        for req in self.requests_with_params:
            if req['url'] == url and req['method'] == method:
                if not force:
                    return  # Skip duplicate
        
        # Determine parameter types present
        param_types = []
        if url_params:
            param_types.append("URL")
        if body_params:
            param_types.append("Body")
        if cookie_params:
            param_types.append("Cookie")
        
        param_type_str = "+".join(param_types) if param_types else "None"
        
        # Create parameter summary
        all_params = {}
        all_params.update(url_params)
        all_params.update(body_params)
        all_params.update(cookie_params)
        
        param_names = list(all_params.keys())
        param_summary = ", ".join(param_names[:5])
        if len(param_names) > 5:
            param_summary += " (+{} more)".format(len(param_names) - 5)
        
        if not param_summary:
            param_summary = "(no params detected)"
        
        # Store request data
        request_data = {
            "url": url,
            "method": method,
            "url_params": url_params,
            "body_params": body_params,
            "cookie_params": cookie_params,
            "all_params": all_params,
            "param_types": param_types,
            "messageInfo": messageInfo,
            "request_info": request_info
        }
        self.requests_with_params.append(request_data)
        
        # Add to table
        def update_table():
            self.table_model.addRow([
                str(len(self.requests_with_params)),
                method,
                url[:40] + "..." if len(url) > 40 else url,
                str(total_params),
                param_type_str,
                param_summary
            ])
            self._update_stats()
        
        SwingUtilities.invokeLater(update_table)
    
    def _extract_all_parameters(self, messageInfo, request_info):
        """Extract URL, body, and cookie parameters"""
        url_params = {}
        body_params = {}
        cookie_params = {}
        
        # Extract standard parameters using Burp's API
        for param in request_info.getParameters():
            param_name = param.getName()
            param_value = param.getValue()
            param_type = param.getType()
            
            if param_type == 0:  # URL parameter
                url_params[param_name] = param_value
            elif param_type == 1:  # Body parameter
                body_params[param_name] = param_value
            elif param_type == 2:  # Cookie
                cookie_params[param_name] = param_value
        
        # Additional extraction from raw request body for complex formats
        request = messageInfo.getRequest()
        body_offset = request_info.getBodyOffset()
        
        if body_offset < len(request):
            try:
                body = request[body_offset:].tostring()
                content_type = self._get_content_type(request_info)
                
                # Handle JSON parameters
                if "json" in content_type.lower() and body.strip():
                    json_params = self._extract_json_params(body)
                    body_params.update(json_params)
                
                # Handle XML parameters
                elif "xml" in content_type.lower() and body.strip():
                    xml_params = self._extract_xml_params(body)
                    body_params.update(xml_params)
            
            except Exception as e:
                pass
        
        return url_params, body_params, cookie_params
    
    def _get_content_type(self, request_info):
        """Extract Content-Type header"""
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return ""
    
    def _extract_json_params(self, body):
        """Extract parameters from JSON body"""
        try:
            import json
            data = json.loads(body)
            
            def flatten_dict(obj, prefix=""):
                """Flatten nested JSON to key-value pairs"""
                params = {}
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        full_key = "{}.{}".format(prefix, key) if prefix else key
                        if isinstance(value, (dict, list)):
                            params.update(flatten_dict(value, full_key))
                        else:
                            params[full_key] = str(value)
                elif isinstance(obj, list):
                    if len(obj) > 0 and isinstance(obj[0], dict):
                        params.update(flatten_dict(obj[0], prefix))
                return params
            
            return flatten_dict(data)
        
        except Exception as e:
            return {}
    
    def _extract_xml_params(self, body):
        """Extract parameters from XML body"""
        params = {}
        try:
            # Extract element text content
            element_pattern = r'<([a-zA-Z_][a-zA-Z0-9_:-]*)>([^<]+)</\1>'
            matches = re.findall(element_pattern, body)
            
            for elem_name, elem_value in matches:
                if ':' in elem_name:
                    elem_name = elem_name.split(':')[1]
                params[elem_name] = elem_value.strip()
            
            # Extract attributes
            attr_pattern = r'<[^>]+\s([a-zA-Z_][a-zA-Z0-9_:-]*)=["\']([^"\']+)["\']'
            attr_matches = re.findall(attr_pattern, body)
            
            for attr_name, attr_value in attr_matches:
                if ':' in attr_name:
                    attr_name = attr_name.split(':')[1]
                params[attr_name] = attr_value
        
        except Exception as e:
            pass
        
        return params
    
    def _update_stats(self):
        """Update the statistics display"""
        total = len(self.requests_with_params)
        
        # Count by parameter type
        type_counts = {"URL": 0, "Body": 0, "Cookie": 0}
        param_count_dist = {}
        
        for req in self.requests_with_params:
            for param_type in req['param_types']:
                type_counts[param_type] = type_counts.get(param_type, 0) + 1
            
            total_params = len(req['all_params'])
            param_count_dist[total_params] = param_count_dist.get(total_params, 0) + 1
        
        stats_text = "<html>"
        stats_text += "<b>Total Requests Captured: {}</b><br><br>".format(total)
        
        if total > 0:
            stats_text += "<b>Parameter Locations:</b><br>"
            for loc, count in sorted(type_counts.items()):
                if count > 0:
                    stats_text += "  {}: {}<br>".format(loc, count)
            
            stats_text += "<br><b>Parameter Count Distribution:</b><br>"
            for count, num_requests in sorted(param_count_dist.items()):
                stats_text += "  {} param(s): {} request(s)<br>".format(count, num_requests)
        else:
            stats_text += "<br>Right-click any request in Proxy/Target<br>"
            stats_text += "and select 'Send to HPP Generator'"
        
        stats_text += "</html>"
        
        self.stats_label.setText(stats_text)
    
    def on_row_selected(self, row):
        """Handle row selection - generate HPP payloads"""
        if row < 0 or row >= len(self.requests_with_params):
            return
        
        self.selected_request = self.requests_with_params[row]
        self._generate_hpp_payloads()
    
    def _generate_hpp_payloads(self):
        """Generate HPP test payloads for the selected request"""
        if not self.selected_request:
            return
        
        url_params = self.selected_request['url_params']
        body_params = self.selected_request['body_params']
        cookie_params = self.selected_request['cookie_params']
        all_params = self.selected_request['all_params']
        
        output = []
        output.append("="*80)
        output.append("HTTP PARAMETER POLLUTION (HPP) TEST PAYLOADS")
        output.append("="*80)
        output.append("")
        output.append("Request: {} {}".format(
            self.selected_request['method'],
            self.selected_request['url']
        ))
        output.append("")
        output.append("Parameters Found: {}".format(len(all_params)))
        output.append("")
        
        # Show parameter breakdown
        if url_params:
            output.append("URL Parameters ({}):".format(len(url_params)))
            for key, value in url_params.items():
                output.append("  {} = {}".format(key, value))
            output.append("")
        
        if body_params:
            output.append("Body Parameters ({}):".format(len(body_params)))
            for key, value in list(body_params.items())[:10]:
                output.append("  {} = {}".format(key, value))
            if len(body_params) > 10:
                output.append("  ... and {} more".format(len(body_params) - 10))
            output.append("")
        
        if cookie_params:
            output.append("Cookie Parameters ({}):".format(len(cookie_params)))
            for key, value in cookie_params.items():
                output.append("  {} = {}".format(key, value[:50] + "..." if len(value) > 50 else value))
            output.append("")
        
        output.append("="*80)
        output.append("GENERATED HPP TEST PAYLOADS")
        output.append("="*80)
        output.append("")
        
        total_payloads = 0
        
        # Generate payloads for URL parameters (most common for HPP)
        if url_params:
            output.append("-"*80)
            output.append("URL PARAMETER POLLUTION PAYLOADS")
            output.append("-"*80)
            output.append("")
            
            # Single parameter variations
            for param_name, param_value in url_params.items():
                output.append("# Payloads for parameter: {}".format(param_name))
                output.append("")
                
                variations = self._generate_single_param_variations(param_name, param_value)
                
                for i, variation in enumerate(variations, 1):
                    output.append("{}. {}".format(i, variation))
                    total_payloads += 1
                
                output.append("")
            
            # Multi-parameter variations
            if len(url_params) > 1:
                output.append("# Multi-Parameter Pollution Payloads")
                output.append("")
                
                multi_variations = self._generate_multi_param_variations(url_params)
                
                for i, variation in enumerate(multi_variations, 1):
                    output.append("{}. {}".format(i, variation))
                    total_payloads += 1
                
                output.append("")
        
        # Generate payloads for body parameters
        if body_params and len(body_params) <= 10:  # Only for reasonable number of params
            output.append("-"*80)
            output.append("BODY PARAMETER POLLUTION PAYLOADS")
            output.append("-"*80)
            output.append("")
            
            for param_name, param_value in list(body_params.items())[:5]:
                output.append("# Payloads for body parameter: {}".format(param_name))
                output.append("")
                
                variations = self._generate_single_param_variations(param_name, param_value)
                
                for i, variation in enumerate(variations[:10], 1):  # Limit to 10 per param
                    output.append("{}. {}".format(i, variation))
                    total_payloads += 1
                
                output.append("")
        
        # Generate payloads for cookies (limited set)
        if cookie_params:
            output.append("-"*80)
            output.append("COOKIE POLLUTION PAYLOADS")
            output.append("-"*80)
            output.append("")
            
            for param_name, param_value in list(cookie_params.items())[:3]:
                output.append("# Payloads for cookie: {}".format(param_name))
                output.append("")
                
                variations = self._generate_cookie_variations(param_name, param_value)
                
                for i, variation in enumerate(variations, 1):
                    output.append("{}. {}".format(i, variation))
                    total_payloads += 1
                
                output.append("")
        
        output.append("="*80)
        output.append("TESTING GUIDE")
        output.append("="*80)
        output.append("")
        output.append("How to test for HPP vulnerabilities:")
        output.append("")
        output.append("1. URL Parameters:")
        output.append("   - Replace the query string with each payload")
        output.append("   - Send requests via Repeater and observe behavior")
        output.append("   - Look for: First/last param wins, concatenation, array behavior")
        output.append("")
        output.append("2. Body Parameters:")
        output.append("   - Modify POST data with duplicate parameters")
        output.append("   - Test different parameter positions")
        output.append("   - Check how backend processes duplicates")
        output.append("")
        output.append("3. Cookies:")
        output.append("   - Set multiple cookies with same name")
        output.append("   - Observe which value is processed")
        output.append("")
        output.append("4. Common HPP Vulnerabilities:")
        output.append("   - Authentication bypass via duplicate params")
        output.append("   - Input validation bypass")
        output.append("   - SQL injection via concatenated params")
        output.append("   - XSS via duplicate parameter injection")
        output.append("   - Access control bypass")
        output.append("")
        output.append("5. Platform-Specific Behavior:")
        output.append("   - PHP: Last parameter wins")
        output.append("   - ASP.NET: Comma-separated concatenation")
        output.append("   - Java: First parameter wins")
        output.append("   - Node.js: Array of values")
        output.append("")
        output.append("Total Payloads Generated: {}".format(total_payloads))
        output.append("")
        
        self.payload_text_area.setText("\n".join(output))
        self.payload_info_label.setText(
            "<html><b>Generated {} HPP test payloads - Ready for testing!</b></html>".format(total_payloads)
        )
    
    def _generate_single_param_variations(self, param_name, param_value):
        """Generate HPP variations for a single parameter"""
        variations = []
        
        # Duplicate parameter (basic HPP)
        variations.extend([
            "{}={}&{}={}".format(param_name, param_value, param_name, param_value),
            "{}={}&{}=modified".format(param_name, param_value, param_name),
            "{}=modified&{}={}".format(param_name, param_name, param_value),
            "{}={}&{}={}&{}=third".format(param_name, param_value, param_name, param_value, param_name),
        ])
        
        # Empty/Null value duplicates
        variations.extend([
            "{}=".format(param_name),
            "{}=&{}={}".format(param_name, param_name, param_value),
            "{}={}&{}=".format(param_name, param_value, param_name),
            "{}".format(param_name),
            "{}=null".format(param_name),
            "{}=NULL".format(param_name),
            "{}=%00".format(param_name),
            "{}=%20".format(param_name),
        ])
        
        # Special character injection
        variations.extend([
            "{}={}%00&{}=injected".format(param_name, param_value, param_name),
            "{}={}%26{}=injected".format(param_name, param_value, param_name),
            "{}={}%23{}=injected".format(param_name, param_value, param_name),
            "{}={};{}=injected".format(param_name, param_value, param_name),
            "{}[]={}&{}[]=value2".format(param_name, param_value, param_name),
            "{}[0]={}".format(param_name, param_value),
            "{}[1]={}".format(param_name, param_value),
        ])
        
        # Injection payloads
        variations.extend([
            "{}={}&{}=<script>alert(1)</script>".format(param_name, param_value, param_name),
            "{}={}&{}='OR'1'='1".format(param_name, param_value, param_name),
            "{}={}&{}=admin".format(param_name, param_value, param_name),
            "{}={}&{}=true".format(param_name, param_value, param_name),
            "{}={}&{}=1".format(param_name, param_value, param_name),
            "{}={}&{}=0".format(param_name, param_value, param_name),
        ])
        
        # Line break injections
        variations.extend([
            "{}={}%0a{}=injected".format(param_name, param_value, param_name),
            "{}={}%0d%0a{}=injected".format(param_name, param_value, param_name),
            "{}={}%0d{}=injected".format(param_name, param_value, param_name),
        ])
        
        return variations
    
    def _generate_multi_param_variations(self, params):
        """Generate HPP variations considering multiple parameters together"""
        variations = []
        param_list = list(params.items())
        
        if len(param_list) < 2:
            return variations
        
        # Original query string
        original = '&'.join(["{}={}".format(k, v) for k, v in param_list])
        
        # Duplicate first param at different positions
        first_key, first_val = param_list[0]
        rest = '&'.join(["{}={}".format(k, v) for k, v in param_list[1:]])
        variations.extend([
            "{}={}&{}=injected&{}".format(first_key, first_val, first_key, rest),
            "{}={}&{}&{}=injected".format(first_key, first_val, rest, first_key),
            "{}=injected&{}={}&{}".format(first_key, first_key, first_val, rest),
        ])
        
        # Duplicate last param at different positions
        last_key, last_val = param_list[-1]
        beginning = '&'.join(["{}={}".format(k, v) for k, v in param_list[:-1]])
        variations.extend([
            "{}=injected&{}&{}={}".format(last_key, beginning, last_key, last_val),
            "{}&{}={}&{}=injected".format(beginning, last_key, last_val, last_key),
            "{}&{}=injected&{}={}".format(beginning, last_key, last_key, last_val),
        ])
        
        # Duplicate middle param if exists
        if len(param_list) >= 3:
            mid_idx = len(param_list) // 2
            mid_key, mid_val = param_list[mid_idx]
            before = '&'.join(["{}={}".format(k, v) for k, v in param_list[:mid_idx]])
            after = '&'.join(["{}={}".format(k, v) for k, v in param_list[mid_idx+1:]])
            variations.extend([
                "{}&{}={}&{}=injected&{}".format(before, mid_key, mid_val, mid_key, after),
                "{}=injected&{}&{}={}&{}".format(mid_key, before, mid_key, mid_val, after),
            ])
        
        # Inject new param between existing ones
        variations.extend([
            "{}={}&injected=malicious&{}".format(param_list[0][0], param_list[0][1], 
                                                 '&'.join(["{}={}".format(k, v) for k, v in param_list[1:]])),
            "{}&injected=malicious&{}={}".format(
                '&'.join(["{}={}".format(k, v) for k, v in param_list[:-1]]),
                param_list[-1][0], param_list[-1][1]
            ),
        ])
        
        # Null byte injections between params
        variations.extend([
            original.replace('&', '%00&', 1),
            original.replace('&', '&%00', 1),
            original.replace('&', '%26', 1),
        ])
        
        # All params duplicated
        all_duplicated = '&'.join(["{}={}&{}={}".format(k, v, k, v) for k, v in param_list])
        variations.append(all_duplicated)
        
        # Parameter reordering
        reversed_params = '&'.join(["{}={}".format(k, v) for k, v in reversed(param_list)])
        variations.append(reversed_params)
        
        # Remove random parameter
        if len(param_list) > 2:
            without_first = '&'.join(["{}={}".format(k, v) for k, v in param_list[1:]])
            variations.append(without_first)
        
        return variations
    
    def _generate_cookie_variations(self, cookie_name, cookie_value):
        """Generate cookie pollution payloads"""
        variations = []
        
        # Duplicate cookie format
        variations.extend([
            "{}={}; {}={}".format(cookie_name, cookie_value, cookie_name, cookie_value),
            "{}={}; {}=modified".format(cookie_name, cookie_value, cookie_name),
            "{}=modified; {}={}".format(cookie_name, cookie_name, cookie_value),
            "{}=; {}={}".format(cookie_name, cookie_name, cookie_value),
            "{}={}; {}=".format(cookie_name, cookie_value, cookie_name),
        ])
        
        return variations
    
    def copy_payloads_to_clipboard(self):
        """Copy all payloads to clipboard"""
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        
        text = self.payload_text_area.getText()
        selection = StringSelection(text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, selection)
        
        self.payload_info_label.setText(
            "<html><b><font color='green'>Payloads copied to clipboard!</font></b></html>"
        )
    
    def send_to_repeater(self):
        """Send original request to Repeater"""
        if not self.selected_request:
            return
        
        messageInfo = self.selected_request['messageInfo']
        request_info = self.selected_request['request_info']
        
        host = request_info.getUrl().getHost()
        port = request_info.getUrl().getPort()
        use_https = request_info.getUrl().getProtocol() == "https"
        
        self._callbacks.sendToRepeater(
            host,
            port,
            use_https,
            messageInfo.getRequest(),
            "HPP: {} params".format(len(self.selected_request['all_params']))
        )
        
        self.payload_info_label.setText(
            "<html><b><font color='blue'>Request sent to Repeater!</font></b></html>"
        )
    
    def send_to_intruder(self):
        """Send original request to Intruder"""
        if not self.selected_request:
            return
        
        messageInfo = self.selected_request['messageInfo']
        request_info = self.selected_request['request_info']
        
        host = request_info.getUrl().getHost()
        port = request_info.getUrl().getPort()
        use_https = request_info.getUrl().getProtocol() == "https"
        
        self._callbacks.sendToIntruder(
            host,
            port,
            use_https,
            messageInfo.getRequest()
        )
        
        self.payload_info_label.setText(
            "<html><b><font color='purple'>Request sent to Intruder!</font></b></html>"
        )
    
    def clear_all_requests(self):
        """Clear all requests from the table"""
        self.requests_with_params = []
        self.selected_request = None
        self.table_model.setRowCount(0)
        self.payload_text_area.setText("All requests cleared.\n\nWaiting for new requests...")
        self.payload_info_label.setText(
            "<html><b>Cleared all requests. Click on a new request to generate payloads.</b></html>"
        )
        self._update_stats()
    
    def getHttpService(self):
        return self.current_request.getHttpService() if self.current_request else None
    
    def getRequest(self):
        return self.current_request.getRequest() if self.current_request else None
    
    def getResponse(self):
        return self.current_response if self.current_response else None


class TableMouseListener(MouseAdapter):
    """Mouse listener for table row selection"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def mouseClicked(self, event):
        table = event.getSource()
        row = table.getSelectedRow()
        if row >= 0:
            self.extender.on_row_selected(row)


class ContextMenuListener:
    """Listener for context menu item"""
    
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            for message in messages:
                self.extender.add_request_from_context_menu(message)


class CopyButtonListener:
    """Action listener for Copy button"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.copy_payloads_to_clipboard()


class SendToRepeaterListener:
    """Action listener for Send to Repeater button"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.send_to_repeater()


class SendToIntruderListener:
    """Action listener for Send to Intruder button"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.send_to_intruder()


class ClearButtonListener:
    """Action listener for Clear button"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.clear_all_requests()
