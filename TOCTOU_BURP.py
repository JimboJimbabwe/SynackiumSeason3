from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, 
                         JButton, BoxLayout, BorderFactory, JFileChooser,
                         JMenuItem)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout
from java.util import ArrayList
import json
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("TOCTOU Request Analyzer")
        
        # Data storage - each entry will be analyzed and prepared for JSON
        self.filtered_requests = []
        self.request_index = 0
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        print("="*70)
        print("TOCTOU Request Analyzer loaded!")
        print("Filtering: Only requests with URL or Body parameters")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI panel"""
        self._main_panel = JPanel(BorderLayout())
        
        # Top panel - Controls
        controls_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self.export_button = JButton("Export to JSON", actionPerformed=self.export_to_json)
        self.clear_button = JButton("Clear All", actionPerformed=self.clear_data)
        
        controls_panel.add(self.export_button)
        controls_panel.add(self.clear_button)
        
        # Table for filtered requests
        table_panel = JPanel(BorderLayout())
        table_panel.setBorder(BorderFactory.createTitledBorder(
            "Filtered Requests (URL or Body Parameters Only)"))
        
        column_names = ["Index", "Method", "URL", "Param Count", "Content-Type"]
        self.table_model = DefaultTableModel(column_names, 0)
        self.request_table = JTable(self.table_model)
        
        scroll_pane = JScrollPane(self.request_table)
        table_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Assemble
        self._main_panel.add(controls_panel, BorderLayout.NORTH)
        self._main_panel.add(table_panel, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "TOCTOU Analyzer"
    
    def getUiComponent(self):
        return self._main_panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process each HTTP message - filter for requests with parameters"""
        if messageIsRequest:
            return
        
        # Analyze request
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Check for URL or Body parameters only
        has_relevant_params = False
        param_count = 0
        
        for param in request_info.getParameters():
            param_type = param.getType()
            # Type 0 = URL param, Type 1 = Body param
            if param_type == 0 or param_type == 1:
                has_relevant_params = True
                param_count += 1
        
        if not has_relevant_params:
            return  # Skip requests without URL/Body params
        
        # Analyze this request
        analyzed_data = self._analyze_request(messageInfo)
        
        if analyzed_data:
            self.filtered_requests.append(analyzed_data)
            
            # Add to table
            self.table_model.addRow([
                str(analyzed_data['index']),
                analyzed_data['method'],
                analyzed_data['url'][:80] + "..." if len(analyzed_data['url']) > 80 else analyzed_data['url'],
                str(param_count),
                analyzed_data['content_type']
            ])
    
    def _analyze_request(self, messageInfo):
        """
        Analyze a request and prepare data structure for JSON export
        Returns dictionary with full curl command AND parsed components
        """
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            request_bytes = messageInfo.getRequest()
            
            self.request_index += 1
            index = self.request_index
            
            # Basic info
            method = request_info.getMethod()
            url = str(request_info.getUrl())
            headers_list = list(request_info.getHeaders())
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = ""
            if body_offset < len(request_bytes):
                body = self._helpers.bytesToString(request_bytes[body_offset:])
            
            # Generate curl command
            curl_command = self._generate_curl_command(method, url, headers_list, body)
            
            # Parse components from curl/request
            components = self._parse_request_components(method, url, headers_list, body)
            
            # Build the data structure
            analyzed_data = {
                'index': index,
                'method': method,
                'url': url,
                'content_type': components['content_type'],
                'curl_command': curl_command,
                'components': components,
                'messageInfo': messageInfo  # Keep for context menu access
            }
            
            return analyzed_data
            
        except Exception as e:
            print("Error analyzing request: {}".format(str(e)))
            return None
    
    def _generate_curl_command(self, method, url, headers_list, body):
        """Generate a curl command from request components"""
        curl_parts = ["curl"]
        
        # Add method if not GET
        if method != "GET":
            curl_parts.append("-X {}".format(method))
        
        # Add headers (skip the first line which is the request line)
        for header in headers_list[1:]:
            # Skip certain headers that curl adds automatically
            if not any(header.lower().startswith(skip) for skip in 
                      ['content-length:', 'host:']):
                curl_parts.append("-H '{}'".format(header.replace("'", "'\\''")))
        
        # Add body if present
        if body and body.strip():
            # Escape single quotes in body
            escaped_body = body.replace("'", "'\\''")
            curl_parts.append("-d '{}'".format(escaped_body))
        
        # Add URL (always last)
        curl_parts.append("'{}'".format(url))
        
        return " ".join(curl_parts)
    
    def _parse_request_components(self, method, url, headers_list, body):
        """
        Parse request into components for the custom format
        Returns dict with: url, headers array, request type, data, content_type
        """
        components = {
            'url': url,
            'request': method,
            'headers': [],
            'cookies': [],
            'data': body if body else None,
            'content_type': 'text/plain'
        }
        
        # Parse headers (skip first line which is request line)
        for header in headers_list[1:]:
            if ':' in header:
                header_name, header_value = header.split(':', 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                
                # Extract content-type
                if header_name.lower() == 'content-type':
                    components['content_type'] = header_value
                
                # Separate cookies from other headers
                if header_name.lower() == 'cookie':
                    # Split multiple cookies
                    cookie_pairs = header_value.split(';')
                    for cookie in cookie_pairs:
                        cookie = cookie.strip()
                        if cookie:
                            components['cookies'].append(cookie)
                else:
                    # Regular header
                    components['headers'].append("{}: {}".format(header_name, header_value))
        
        return components
    
    def export_to_json(self, event):
        """Export all analyzed requests to JSON file"""
        if not self.filtered_requests:
            print("No requests to export!")
            return
        
        # Create JSON structure
        json_data = {
            'metadata': {
                'total_requests': len(self.filtered_requests),
                'export_date': str(java.util.Date()),
                'format_version': '1.0'
            },
            'requests': []
        }
        
        # Add each request
        for req_data in self.filtered_requests:
            # Create clean copy without messageInfo (not JSON serializable)
            clean_data = {
                'index': req_data['index'],
                'method': req_data['method'],
                'url': req_data['url'],
                'content_type': req_data['content_type'],
                'curl_command': req_data['curl_command'],
                'components': {
                    'url': req_data['components']['url'],
                    'request': req_data['components']['request'],
                    'headers': req_data['components']['headers'],
                    'cookies': req_data['components']['cookies'],
                    'data': req_data['components']['data'],
                    'content_type': req_data['components']['content_type']
                }
            }
            
            json_data['requests'].append(clean_data)
        
        # File chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save JSON Export")
        file_chooser.setSelectedFile(java.io.File("toctou_requests.json"))
        
        result = file_chooser.showSaveDialog(self._main_panel)
        
        if result == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            
            try:
                with open(file_path, 'w') as f:
                    json.dump(json_data, f, indent=2)
                
                print("="*70)
                print("Exported {} requests to: {}".format(len(self.filtered_requests), file_path))
                print("="*70)
                
            except Exception as e:
                print("Error writing JSON: {}".format(str(e)))
    
    def clear_data(self, event):
        """Clear all stored data"""
        self.filtered_requests = []
        self.request_index = 0
        self.table_model.setRowCount(0)
        print("Cleared all data")
    
    def createMenuItems(self, invocation):
        """Context menu for right-clicking requests"""
        menu_items = ArrayList()
        
        # Only show menu for requests in Proxy history
        if invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY:
            menu_item = JMenuItem("Send to TOCTOU Analyzer")
            menu_item.addActionListener(
                lambda x: self._handle_context_menu(invocation)
            )
            menu_items.add(menu_item)
        
        return menu_items
    
    def _handle_context_menu(self, invocation):
        """Handle context menu selection"""
        messages = invocation.getSelectedMessages()
        
        for messageInfo in messages:
            analyzed_data = self._analyze_request(messageInfo)
            
            if analyzed_data:
                self.filtered_requests.append(analyzed_data)
                
                self.table_model.addRow([
                    str(analyzed_data['index']),
                    analyzed_data['method'],
                    analyzed_data['url'][:80],
                    "-",
                    analyzed_data['content_type']
                ])
        
        print("Added {} request(s) to analyzer".format(len(messages)))


# Import for date handling
import java.util.Date
import java.io.File
