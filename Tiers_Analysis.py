from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, 
                         JTextArea, JLabel, BoxLayout, BorderFactory)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Color
from java.lang import Object
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Security Tier Analyzer (Enhanced)")
        
        # Data storage
        self.tier_data = {1: [], 2: [], 3: [], 4: []}
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        print("="*70)
        print("Security Tier Analyzer (Enhanced) loaded successfully!")
        print("="*70)
        print("Enhanced features:")
        print("  - GraphQL query/mutation detection")
        print("  - Nested JSON field extraction")
        print("  - XML element and attribute detection")
        print("  - Standard form/URL parameter detection")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI panel"""
        self._main_panel = JPanel(BorderLayout())
        
        # Create split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Top panel - Statistics
        stats_panel = JPanel()
        stats_panel.setLayout(BoxLayout(stats_panel, BoxLayout.Y_AXIS))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        
        self.stats_label = JLabel("Waiting for requests...")
        stats_panel.add(self.stats_label)
        
        # Bottom panel - Tiered table
        table_panel = JPanel(BorderLayout())
        table_panel.setBorder(BorderFactory.createTitledBorder("Requests by Security Tier"))
        
        # Create table model
        column_names = ["Tier", "Index", "Method", "URL", "Input Type", "Parameters", "Security Info"]
        self.table_model = DefaultTableModel(column_names, 0)
        self.request_table = JTable(self.table_model)
        
        # Custom renderer for tier column (color-coded)
        self.request_table.setDefaultRenderer(
            Object, 
            TierCellRenderer()
        )
        
        scroll_pane = JScrollPane(self.request_table)
        table_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Add to split pane
        split_pane.setTopComponent(stats_panel)
        split_pane.setBottomComponent(table_panel)
        split_pane.setDividerLocation(100)
        
        self._main_panel.add(split_pane, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "Tier Analyzer+"
    
    def getUiComponent(self):
        return self._main_panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process each HTTP message"""
        # Only process responses (so we have both request and response)
        if messageIsRequest:
            return
        
        # Analyze the request/response pair
        tier = self._calculate_tier(messageInfo)
        
        if tier is None:
            return  # No parameters, skip
        
        # Extract details
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())
        method = request_info.getMethod()
        
        # Get parameters and input type
        params, input_type = self._extract_parameters_enhanced(messageInfo)
        
        if not params:
            return  # No inputs detected
        
        param_str = ", ".join(params[:5])  # Show first 5 params
        if len(params) > 5:
            param_str += " (+{} more)".format(len(params)-5)
        
        # Get security info
        security_info = self._get_security_info(messageInfo)
        
        # Store in tier data
        request_data = {
            "url": url,
            "method": method,
            "params": params,
            "input_type": input_type,
            "security_info": security_info,
            "messageInfo": messageInfo
        }
        self.tier_data[tier].append(request_data)
        
        # Add to table
        self.table_model.addRow([
            "Tier {}".format(tier),
            str(len(self.tier_data[tier])),
            method,
            url[:60] + "..." if len(url) > 60 else url,
            input_type,
            param_str,
            security_info
        ])
        
        # Update statistics
        self._update_stats()
    
    def _calculate_tier(self, messageInfo):
        """Calculate security tier for a request"""
        request_info = self._helpers.analyzeRequest(messageInfo)
        response = messageInfo.getResponse()
        
        if response is None:
            return None
        
        # Check if has parameters (using enhanced detection)
        params, _ = self._extract_parameters_enhanced(messageInfo)
        if not params:
            return None
        
        # Analyze response
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        # Tier 1: XSS Protection = 0
        for header in headers:
            if "x-xss-protection" in header.lower() and "0" in header:
                return 1
        
        # Tier 2: PHP content
        for header in headers:
            if "content-type" in header.lower():
                if "php" in header.lower() or "text/html" in header.lower():
                    url = str(request_info.getUrl())
                    if ".php" in url.lower():
                        return 2
        
        # Tier 3: JSON content
        for header in headers:
            if "content-type" in header.lower() and "json" in header.lower():
                return 3
        
        # Tier 4: Everything else with parameters
        return 4
    
    def _extract_parameters_enhanced(self, messageInfo):
        """
        Extract all parameters from request - ENHANCED VERSION
        Returns: (list of params, input_type string)
        """
        request_info = self._helpers.analyzeRequest(messageInfo)
        params = []
        input_types = []
        
        # Get standard parameters (URL, form data, cookies)
        standard_params = []
        for param in request_info.getParameters():
            param_name = param.getName()
            param_type = param.getType()  # 0=URL, 1=Body, 2=Cookie
            
            if param_name not in standard_params:
                standard_params.append(param_name)
                
                if param_type == 0:
                    input_types.append("URL")
                elif param_type == 1:
                    input_types.append("Form")
                elif param_type == 2:
                    input_types.append("Cookie")
        
        params.extend(standard_params)
        
        # Get request body for additional analysis
        request = messageInfo.getRequest()
        body_offset = request_info.getBodyOffset()
        
        if body_offset < len(request):
            try:
                body = request[body_offset:].tostring()
                content_type = self._get_content_type(request_info)
                
                # Detect GraphQL
                if self._is_graphql(body):
                    input_types.append("GraphQL")
                    graphql_fields = self._extract_graphql_fields(body)
                    params.extend(graphql_fields)
                
                # Detect JSON with nested fields
                elif "json" in content_type.lower() and body.strip():
                    json_params = self._extract_json_params(body)
                    if json_params:
                        input_types.append("JSON")
                        params.extend(json_params)
                
                # Detect XML
                elif "xml" in content_type.lower() or (body.strip() and body.strip().startswith("<?xml")):
                    input_types.append("XML")
                    xml_params = self._extract_xml_params(body)
                    params.extend(xml_params)
                
                # Detect SOAP
                elif "soap" in content_type.lower() or "soap:Envelope" in body:
                    input_types.append("SOAP")
                    xml_params = self._extract_xml_params(body)
                    params.extend(xml_params)
            
            except Exception as e:
                print("Error parsing body: {}".format(str(e)))
        
        # Create input type string
        if not input_types:
            input_type_str = "Unknown"
        else:
            # Remove duplicates and join
            unique_types = []
            for t in input_types:
                if t not in unique_types:
                    unique_types.append(t)
            input_type_str = "+".join(unique_types)
        
        return params, input_type_str
    
    def _get_content_type(self, request_info):
        """Extract Content-Type header"""
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return ""
    
    def _is_graphql(self, body):
        """Detect if body contains GraphQL query/mutation"""
        try:
            # Import json for GraphQL detection (often sent as JSON)
            import json
            
            # Try parsing as JSON first (GraphQL is often in JSON wrapper)
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Check for GraphQL structure in JSON
                    if "query" in data or "mutation" in data:
                        return True
            except:
                pass
            
            # Check raw body for GraphQL keywords
            graphql_keywords = ["query", "mutation", "subscription", "fragment"]
            body_lower = body.lower()
            
            # Check for GraphQL structure
            has_keyword = any(keyword in body_lower for keyword in graphql_keywords)
            has_braces = "{" in body and "}" in body
            
            # Additional check for GraphQL-like structure
            has_field_pattern = re.search(r'\w+\s*\{', body) is not None
            
            return has_keyword and has_braces and has_field_pattern
        
        except Exception as e:
            return False
    
    def _extract_graphql_fields(self, body):
        """Extract field names from GraphQL queries"""
        fields = []
        
        try:
            # Try to parse as JSON first (GraphQL often wrapped in JSON)
            import json
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    if "query" in data:
                        body = data["query"]
                    elif "mutation" in data:
                        body = data["mutation"]
            except:
                pass
            
            # Match field patterns like: fieldName, fieldName(args), fieldName:alias
            # This regex captures field names in GraphQL syntax
            field_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(|:|\{)'
            matches = re.findall(field_pattern, str(body))
            
            # Filter out GraphQL keywords
            keywords = ["query", "mutation", "subscription", "fragment", "on", "type", "input", "enum", "interface", "union", "schema"]
            fields = [m for m in matches if m not in keywords]
            
            # Remove duplicates while preserving order
            seen = set()
            unique_fields = []
            for f in fields:
                if f not in seen:
                    seen.add(f)
                    unique_fields.append("GQL:{}".format(f))
            
            return unique_fields[:15]  # Limit to 15 fields
        
        except Exception as e:
            print("Error extracting GraphQL fields: {}".format(str(e)))
            return []
    
    def _extract_json_params(self, body):
        """Extract all keys from JSON body, including nested"""
        try:
            import json
            data = json.loads(body)
            
            def get_all_keys(obj, prefix="", depth=0):
                """Recursively extract all keys from nested JSON"""
                keys = []
                
                # Limit recursion depth to avoid huge parameter lists
                if depth > 4:
                    return keys
                
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        # Create dotted notation for nested keys
                        if prefix:
                            full_key = "{}.{}".format(prefix, key)
                        else:
                            full_key = key
                        
                        keys.append("JSON:{}".format(full_key))
                        
                        # Recurse for nested objects/arrays
                        if isinstance(value, (dict, list)):
                            keys.extend(get_all_keys(value, full_key, depth + 1))
                
                elif isinstance(obj, list):
                    # For arrays, analyze first item if it exists
                    if len(obj) > 0 and isinstance(obj[0], (dict, list)):
                        keys.extend(get_all_keys(obj[0], prefix, depth + 1))
                
                return keys
            
            all_keys = get_all_keys(data)
            
            # Limit total keys returned
            return all_keys[:20]
        
        except Exception as e:
            return []
    
    def _extract_xml_params(self, body):
        """Extract element and attribute names from XML"""
        params = []
        
        try:
            # Match element names: <elementName> or <elementName attr="val">
            element_pattern = r'<([a-zA-Z_][a-zA-Z0-9_:-]*)[>\s/]'
            elements = re.findall(element_pattern, body)
            
            # Remove duplicates and common XML/SOAP namespaces
            ignore_elements = ['soap', 'envelope', 'body', 'header', 'xml']
            unique_elements = []
            seen = set()
            
            for elem in elements:
                elem_lower = elem.lower()
                # Strip namespace prefixes (e.g., soap:Body -> Body)
                if ':' in elem:
                    elem = elem.split(':')[1]
                
                if elem not in seen and elem_lower not in ignore_elements:
                    seen.add(elem)
                    unique_elements.append("XML:{}".format(elem))
            
            params.extend(unique_elements[:15])
            
            # Match attribute names: attribute="value" or attribute='value'
            attr_pattern = r'\s([a-zA-Z_][a-zA-Z0-9_:-]*)=["\']'
            attributes = re.findall(attr_pattern, body)
            
            unique_attrs = []
            seen_attrs = set()
            
            for attr in attributes:
                # Strip namespace prefixes
                if ':' in attr:
                    attr = attr.split(':')[1]
                
                if attr not in seen_attrs:
                    seen_attrs.add(attr)
                    unique_attrs.append("XML@{}".format(attr))
            
            params.extend(unique_attrs[:10])
            
            return params
        
        except Exception as e:
            print("Error extracting XML params: {}".format(str(e)))
            return []
    
    def _get_security_info(self, messageInfo):
        """Get security-relevant information"""
        response = messageInfo.getResponse()
        if response is None:
            return ""
        
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        info_parts = []
        
        for header in headers:
            if "x-xss-protection" in header.lower():
                info_parts.append(header)
            elif "content-type" in header.lower():
                # Extract just the content type value
                parts = header.split(":", 1)
                if len(parts) > 1:
                    info_parts.append("CT: {}".format(parts[1].strip()[:30]))
        
        return "; ".join(info_parts)
    
    def _update_stats(self):
        """Update the statistics display"""
        total = sum(len(reqs) for reqs in self.tier_data.values())
        
        # Count input types
        input_type_counts = {}
        for tier_reqs in self.tier_data.values():
            for req in tier_reqs:
                input_type = req.get('input_type', 'Unknown')
                input_type_counts[input_type] = input_type_counts.get(input_type, 0) + 1
        
        stats_text = "<html>"
        stats_text += "<b>Total Requests with Parameters: {}</b><br><br>".format(total)
        stats_text += "<font color='red'>Tier 1 (CRITICAL - XSS Protection Off): {}</font><br>".format(len(self.tier_data[1]))
        stats_text += "<font color='orange'>Tier 2 (HIGH - PHP Content): {}</font><br>".format(len(self.tier_data[2]))
        stats_text += "<font color='blue'>Tier 3 (MEDIUM - JSON Content): {}</font><br>".format(len(self.tier_data[3]))
        stats_text += "Tier 4 (LOW - Other): {}<br><br>".format(len(self.tier_data[4]))
        
        # Add input type breakdown
        if input_type_counts:
            stats_text += "<b>Input Types Detected:</b><br>"
            for input_type, count in sorted(input_type_counts.items()):
                stats_text += "  {}: {}<br>".format(input_type, count)
        
        stats_text += "</html>"
        
        self.stats_label.setText(stats_text)


class TierCellRenderer(DefaultTableCellRenderer):
    """Custom cell renderer to color-code tiers"""
    
    def getTableCellRendererComponent(self, table, value, isSelected, 
                                     hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        
        if column == 0:  # Tier column
            if "Tier 1" in str(value):
                component.setBackground(Color(255, 200, 200))  # Light red
            elif "Tier 2" in str(value):
                component.setBackground(Color(255, 220, 150))  # Light orange
            elif "Tier 3" in str(value):
                component.setBackground(Color(255, 255, 200))  # Light yellow
            else:
                component.setBackground(Color.WHITE)
        else:
            if not isSelected:
                component.setBackground(Color.WHITE)
        
        return component
