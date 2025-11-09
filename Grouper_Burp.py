from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JTable, JScrollPane, JSplitPane, JButton,
                         JTextField, JLabel, BoxLayout, BorderFactory, 
                         JMenuItem, JPopupMenu, JTabbedPane, SwingUtilities,
                         JTextArea, Box)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout, Font
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Object
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Request Grouper & Visualizer")
        
        # Data storage
        self.all_requests = []  # All captured requests
        self.groups = {}  # Dictionary of group_name -> list of request indices
        self.group_colors = {}  # Dictionary of group_name -> color
        self.next_group_id = 1
        
        # Available colors for groups
        self.available_colors = [
            Color(173, 216, 230),  # Light Blue
            Color(144, 238, 144),  # Light Green
            Color(255, 182, 193),  # Light Pink
            Color(221, 160, 221),  # Plum
            Color(255, 218, 185),  # Peach
            Color(176, 224, 230),  # Powder Blue
            Color(255, 250, 205),  # Lemon Chiffon
            Color(216, 191, 216),  # Thistle
            Color(255, 228, 181),  # Moccasin
            Color(230, 230, 250),  # Lavender
        ]
        self.color_index = 0
        
        # Create UI
        self._create_ui()
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        print("="*70)
        print("Request Grouper & Visualizer loaded successfully!")
        print("="*70)
        print("Usage:")
        print("  1. Right-click requests in main table")
        print("  2. Select 'Add to Group' and choose/create group")
        print("  3. View groups in the Groups tab")
        print("  4. Each group has a visual widget showing all related requests")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI with tabbed interface"""
        self._main_panel = JPanel(BorderLayout())
        
        # Create tabbed pane
        self.tabbed_pane = JTabbedPane()
        
        # Tab 1: All Requests (capture table)
        self.requests_panel = self._create_requests_panel()
        self.tabbed_pane.addTab("All Requests", self.requests_panel)
        
        # Tab 2: Groups (visual grouping area)
        self.groups_panel = self._create_groups_panel()
        self.tabbed_pane.addTab("Groups", self.groups_panel)
        
        self._main_panel.add(self.tabbed_pane, BorderLayout.CENTER)
    
    def _create_requests_panel(self):
        """Create the main requests capture panel"""
        panel = JPanel(BorderLayout())
        
        # Top: Statistics
        stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.stats_label = JLabel("Captured: 0 requests")
        stats_panel.add(self.stats_label)
        
        stats_panel.add(JLabel("    |    "))
        
        self.selection_label = JLabel("Selected: 0 requests")
        self.selection_label.setForeground(Color(0, 100, 0))
        self.selection_label.setFont(Font("Arial", Font.BOLD, 12))
        stats_panel.add(self.selection_label)
        
        panel.add(stats_panel, BorderLayout.NORTH)
        
        # Center: Table of all requests
        column_names = ["#", "Method", "URL", "Parameters", "Status", "Length"]
        self.requests_table_model = DefaultTableModel(column_names, 0)
        self.requests_table = JTable(self.requests_table_model)
        self.requests_table.setAutoCreateRowSorter(True)
        
        # Set column widths
        self.requests_table.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.requests_table.getColumnModel().getColumn(1).setPreferredWidth(70)
        self.requests_table.getColumnModel().getColumn(2).setPreferredWidth(400)
        self.requests_table.getColumnModel().getColumn(3).setPreferredWidth(200)
        self.requests_table.getColumnModel().getColumn(4).setPreferredWidth(60)
        self.requests_table.getColumnModel().getColumn(5).setPreferredWidth(80)
        
        # Add mouse listener for right-click context menu
        self.requests_table.addMouseListener(TableMouseListener(self))
        
        # Add selection listener to update selection count
        from javax.swing.event import ListSelectionListener
        
        class SelectionListener(ListSelectionListener):
            def __init__(self, extender):
                self.extender = extender
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    count = len(self.extender.requests_table.getSelectedRows())
                    self.extender.selection_label.setText("Selected: {} requests".format(count))
        
        self.requests_table.getSelectionModel().addListSelectionListener(SelectionListener(self))
        
        scroll_pane = JScrollPane(self.requests_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Bottom: Filter controls and group buttons
        bottom_panel = JPanel()
        bottom_panel.setLayout(BoxLayout(bottom_panel, BoxLayout.X_AXIS))
        bottom_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Filter controls
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_panel.add(JLabel("Filter URL:"))
        self.filter_field = JTextField(30)
        filter_panel.add(self.filter_field)
        
        filter_button = JButton("Apply Filter", actionPerformed=self._apply_filter)
        filter_panel.add(filter_button)
        
        clear_button = JButton("Clear Filter", actionPerformed=self._clear_filter)
        filter_panel.add(clear_button)
        
        bottom_panel.add(filter_panel)
        bottom_panel.add(Box.createHorizontalGlue())
        
        # Group action buttons - MORE PROMINENT
        group_actions_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        group_actions_panel.setBorder(BorderFactory.createTitledBorder("Group Actions"))
        
        create_group_btn = JButton("CREATE GROUP FROM SELECTED", actionPerformed=self._create_group_from_button)
        create_group_btn.setBackground(Color(50, 205, 50))  # Lime green
        create_group_btn.setForeground(Color.WHITE)
        create_group_btn.setFont(Font("Arial", Font.BOLD, 12))
        group_actions_panel.add(create_group_btn)
        
        add_to_group_btn = JButton("Add to Existing Group", actionPerformed=self._add_to_group_from_button)
        add_to_group_btn.setBackground(Color(70, 130, 180))  # Steel blue
        add_to_group_btn.setForeground(Color.WHITE)
        group_actions_panel.add(add_to_group_btn)
        
        bottom_panel.add(group_actions_panel)
        
        panel.add(bottom_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_groups_panel(self):
        """Create the groups visualization panel"""
        panel = JPanel(BorderLayout())
        
        # Top: Controls
        controls_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        refresh_button = JButton("Refresh Groups", actionPerformed=self._refresh_groups_view)
        controls_panel.add(refresh_button)
        
        controls_panel.add(JLabel("    Total Groups:"))
        self.group_count_label = JLabel("0")
        controls_panel.add(self.group_count_label)
        
        panel.add(controls_panel, BorderLayout.NORTH)
        
        # Center: Scrollable panel for group widgets
        self.groups_container = JPanel()
        self.groups_container.setLayout(BoxLayout(self.groups_container, BoxLayout.Y_AXIS))
        
        groups_scroll = JScrollPane(self.groups_container)
        panel.add(groups_scroll, BorderLayout.CENTER)
        
        return panel
    
    def _apply_filter(self, event):
        """Apply URL filter to requests table"""
        filter_text = self.filter_field.getText().lower()
        
        # Clear and repopulate table with filtered results
        self.requests_table_model.setRowCount(0)
        
        for idx, req in enumerate(self.all_requests):
            if filter_text in req['url'].lower():
                self._add_request_to_table(idx, req)
    
    def _clear_filter(self, event):
        """Clear filter and show all requests"""
        self.filter_field.setText("")
        self._apply_filter(None)
    
    def _create_group_from_button(self, event):
        """Create a new group from selected rows using button"""
        from javax.swing import JOptionPane
        
        print("[DEBUG] Create group button clicked!")
        
        selected_rows = self.requests_table.getSelectedRows()
        print("[DEBUG] Selected rows: {}".format(len(selected_rows)))
        
        if not selected_rows or len(selected_rows) == 0:
            print("[DEBUG] No rows selected, showing warning")
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Please select one or more requests first",
                "No Selection",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        print("[DEBUG] Prompting for group name")
        group_name = JOptionPane.showInputDialog(
            self._main_panel,
            "Enter name for new group:",
            "Create New Group",
            JOptionPane.PLAIN_MESSAGE
        )
        
        if group_name:
            print("[DEBUG] Creating group: '{}'".format(group_name))
            self.create_new_group(selected_rows, group_name)
            # Switch to Groups tab to show the result
            self.tabbed_pane.setSelectedIndex(1)
        else:
            print("[DEBUG] Group creation cancelled")
    
    def _add_to_group_from_button(self, event):
        """Add selected rows to an existing group using button"""
        from javax.swing import JOptionPane
        
        selected_rows = self.requests_table.getSelectedRows()
        
        if not selected_rows or len(selected_rows) == 0:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Please select one or more requests first",
                "No Selection",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        if not self.groups:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No groups exist yet. Create one first!",
                "No Groups",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        # Show dialog to select group
        group_names = sorted(self.groups.keys())
        selected_group = JOptionPane.showInputDialog(
            self._main_panel,
            "Select group to add to:",
            "Add to Group",
            JOptionPane.PLAIN_MESSAGE,
            None,
            group_names,
            group_names[0]
        )
        
        if selected_group:
            self.add_to_existing_group(selected_rows, selected_group)
            # Switch to Groups tab to show the result
            self.tabbed_pane.setSelectedIndex(1)
    
    def getTabCaption(self):
        return "Request Grouper"
    
    def getUiComponent(self):
        return self._main_panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Capture HTTP requests with parameters"""
        if messageIsRequest:
            return
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Extract parameters
        params = self._extract_all_parameters(messageInfo)
        
        # Only capture requests with parameters (input points)
        if not params:
            return
        
        # Get response info
        response = messageInfo.getResponse()
        status_code = ""
        response_length = 0
        
        if response:
            response_info = self._helpers.analyzeResponse(response)
            status_code = self._extract_status_code(response_info)
            response_length = len(response)
        
        # Store request data
        request_data = {
            'method': request_info.getMethod(),
            'url': str(request_info.getUrl()),
            'parameters': params,
            'status': status_code,
            'length': response_length,
            'messageInfo': messageInfo,
            'timestamp': self._callbacks.getHelpers().analyzeRequest(messageInfo).getHeaders()[0]
        }
        
        # Add to list
        request_index = len(self.all_requests)
        self.all_requests.append(request_data)
        
        # Add to table
        self._add_request_to_table(request_index, request_data)
        
        # Update stats
        self.stats_label.setText("Captured: {} requests".format(len(self.all_requests)))
    
    def _add_request_to_table(self, index, request_data):
        """Add a request to the display table"""
        url = request_data['url']
        if len(url) > 80:
            url = url[:77] + "..."
        
        param_str = ", ".join(request_data['parameters'][:3])
        if len(request_data['parameters']) > 3:
            param_str += " (+{})".format(len(request_data['parameters']) - 3)
        
        self.requests_table_model.addRow([
            str(index),
            request_data['method'],
            url,
            param_str,
            request_data['status'],
            str(request_data['length'])
        ])
    
    def _extract_all_parameters(self, messageInfo):
        """Extract all parameter names from request"""
        request_info = self._helpers.analyzeRequest(messageInfo)
        params = []
        
        # Get standard parameters
        for param in request_info.getParameters():
            param_name = param.getName()
            if param_name not in params:
                params.append(param_name)
        
        # Check body for JSON/XML/GraphQL
        request = messageInfo.getRequest()
        body_offset = request_info.getBodyOffset()
        
        if body_offset < len(request):
            try:
                body = request[body_offset:].tostring()
                content_type = self._get_content_type(request_info)
                
                # JSON
                if "json" in content_type.lower() and body.strip():
                    json_params = self._extract_json_keys(body)
                    params.extend(json_params)
                
                # XML
                elif "xml" in content_type.lower():
                    xml_params = self._extract_xml_elements(body)
                    params.extend(xml_params)
                
                # GraphQL
                elif self._is_graphql(body):
                    gql_params = self._extract_graphql_fields(body)
                    params.extend(gql_params)
            
            except Exception as e:
                pass
        
        return params
    
    def _get_content_type(self, request_info):
        """Extract Content-Type header"""
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return ""
    
    def _is_graphql(self, body):
        """Detect GraphQL"""
        try:
            body_lower = body.lower()
            return ("query" in body_lower or "mutation" in body_lower) and "{" in body
        except:
            return False
    
    def _extract_json_keys(self, body):
        """Extract top-level keys from JSON"""
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict):
                return list(data.keys())[:10]
        except:
            pass
        return []
    
    def _extract_xml_elements(self, body):
        """Extract XML element names"""
        try:
            pattern = r'<([a-zA-Z_][a-zA-Z0-9_:-]*)[>\s/]'
            elements = re.findall(pattern, body)
            return list(set(elements))[:10]
        except:
            return []
    
    def _extract_graphql_fields(self, body):
        """Extract GraphQL field names"""
        try:
            pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(|:|\{)'
            fields = re.findall(pattern, str(body))
            keywords = ["query", "mutation", "subscription", "fragment", "on"]
            return [f for f in fields if f not in keywords][:10]
        except:
            return []
    
    def _extract_status_code(self, response_info):
        """Extract HTTP status code"""
        headers = response_info.getHeaders()
        if headers and len(headers) > 0:
            status_line = headers[0]
            parts = status_line.split()
            if len(parts) >= 2:
                return parts[1]
        return ""
    
    def createMenuItems(self, invocation):
        """Create context menu for grouping requests"""
        # Get selected messages from Burp (Proxy, Repeater, etc.)
        selected_messages = invocation.getSelectedMessages()
        
        if not selected_messages or len(selected_messages) == 0:
            return None
        
        menu_items = ArrayList()
        
        # Create new group option
        new_group_item = JMenuItem("Create New Group from Selection")
        new_group_item.addActionListener(BurpContextMenuListener(self, selected_messages, None))
        menu_items.add(new_group_item)
        
        # Add to existing groups
        if self.groups:
            for group_name in sorted(self.groups.keys()):
                item = JMenuItem("Add to Group: '{}'".format(group_name))
                item.addActionListener(BurpContextMenuListener(self, selected_messages, group_name))
                menu_items.add(item)
        
        return menu_items
    
    def create_new_group(self, selected_rows, group_name):
        """Create a new group with selected requests"""
        if not group_name or group_name in self.groups:
            return
        
        # Convert view indices to model indices
        request_indices = []
        for view_row in selected_rows:
            model_row = self.requests_table.convertRowIndexToModel(view_row)
            request_idx = int(self.requests_table_model.getValueAt(model_row, 0))
            request_indices.append(request_idx)
        
        # Create group
        self.groups[group_name] = request_indices
        self.group_colors[group_name] = self._get_next_color()
        
        # Refresh groups view
        self._refresh_groups_view(None)
        
        print("Created group '{}' with {} requests".format(group_name, len(request_indices)))
    
    def add_to_existing_group(self, selected_rows, group_name):
        """Add selected requests to existing group"""
        if group_name not in self.groups:
            return
        
        # Convert view indices to model indices
        for view_row in selected_rows:
            model_row = self.requests_table.convertRowIndexToModel(view_row)
            request_idx = int(self.requests_table_model.getValueAt(model_row, 0))
            
            if request_idx not in self.groups[group_name]:
                self.groups[group_name].append(request_idx)
        
        # Refresh groups view
        self._refresh_groups_view(None)
        
        print("Added {} requests to group '{}'".format(len(selected_rows), group_name))
    
    def _get_next_color(self):
        """Get next color for a group"""
        color = self.available_colors[self.color_index % len(self.available_colors)]
        self.color_index += 1
        return color
    
    def _refresh_groups_view(self, event):
        """Refresh the groups visualization panel"""
        # Clear current widgets
        self.groups_container.removeAll()
        
        # Update group count
        self.group_count_label.setText(str(len(self.groups)))
        
        # Create widget for each group
        for group_name in sorted(self.groups.keys()):
            widget = self._create_group_widget(group_name, self.groups[group_name])
            self.groups_container.add(widget)
            self.groups_container.add(Box.createRigidArea(Dimension(0, 10)))
        
        # Refresh UI
        self.groups_container.revalidate()
        self.groups_container.repaint()
    
    def _create_group_widget(self, group_name, request_indices):
        """Create a visual widget for a group of requests"""
        widget = JPanel()
        widget.setLayout(BorderLayout())
        widget.setBorder(BorderFactory.createLineBorder(Color.BLACK, 2))
        widget.setBackground(self.group_colors.get(group_name, Color.WHITE))
        widget.setMaximumSize(Dimension(32767, 300))  # Max width, fixed height
        
        # Header
        header_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        header_panel.setOpaque(False)
        
        title_label = JLabel(group_name)
        title_label.setFont(Font("Arial", Font.BOLD, 16))
        header_panel.add(title_label)
        
        header_panel.add(JLabel("  ({} requests)".format(len(request_indices))))
        
        # Delete button
        delete_btn = JButton("Delete Group", actionPerformed=lambda e: self._delete_group(group_name))
        header_panel.add(delete_btn)
        
        widget.add(header_panel, BorderLayout.NORTH)
        
        # Content: Table of requests in this group
        group_table_model = DefaultTableModel(["#", "Method", "URL", "Parameters"], 0)
        group_table = JTable(group_table_model)
        group_table.setBackground(self.group_colors.get(group_name, Color.WHITE))
        
        for req_idx in request_indices:
            if req_idx < len(self.all_requests):
                req = self.all_requests[req_idx]
                url = req['url']
                if len(url) > 60:
                    url = url[:57] + "..."
                
                params = ", ".join(req['parameters'][:2])
                if len(req['parameters']) > 2:
                    params += " (+{})".format(len(req['parameters']) - 2)
                
                group_table_model.addRow([
                    str(req_idx),
                    req['method'],
                    url,
                    params
                ])
        
        scroll = JScrollPane(group_table)
        scroll.setPreferredSize(Dimension(900, 150))
        widget.add(scroll, BorderLayout.CENTER)
        
        # Footer: Summary stats
        footer_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        footer_panel.setOpaque(False)
        
        # Calculate stats
        methods = {}
        for req_idx in request_indices:
            if req_idx < len(self.all_requests):
                method = self.all_requests[req_idx]['method']
                methods[method] = methods.get(method, 0) + 1
        
        stats_text = "Methods: " + ", ".join(["{}({})".format(m, c) for m, c in methods.items()])
        footer_panel.add(JLabel(stats_text))
        
        widget.add(footer_panel, BorderLayout.SOUTH)
        
        return widget
    
    def add_requests_from_burp_context(self, selected_messages, group_name):
        """Add requests from Burp's context menu (Proxy/Repeater) to a group"""
        from javax.swing import JOptionPane
        
        # If no group name, prompt for new group
        if group_name is None:
            group_name = JOptionPane.showInputDialog(
                None,
                "Enter name for new group:",
                "Create New Group",
                JOptionPane.PLAIN_MESSAGE
            )
            
            if not group_name:
                return
            
            if group_name in self.groups:
                JOptionPane.showMessageDialog(
                    None,
                    "Group '{}' already exists. Adding to existing group.".format(group_name),
                    "Group Exists",
                    JOptionPane.INFORMATION_MESSAGE
                )
        
        # Process each selected message
        request_indices = []
        
        for message in selected_messages:
            # Check if this request already exists in our all_requests list
            request_info = self._helpers.analyzeRequest(message)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            
            # Try to find matching request
            found_index = None
            for idx, req in enumerate(self.all_requests):
                if req['url'] == url and req['method'] == method:
                    found_index = idx
                    break
            
            # If not found, add it
            if found_index is None:
                params = self._extract_all_parameters(message)
                
                response = message.getResponse()
                status_code = ""
                response_length = 0
                
                if response:
                    response_info = self._helpers.analyzeResponse(response)
                    status_code = self._extract_status_code(response_info)
                    response_length = len(response)
                
                request_data = {
                    'method': method,
                    'url': url,
                    'parameters': params,
                    'status': status_code,
                    'length': response_length,
                    'messageInfo': message,
                    'timestamp': ''
                }
                
                found_index = len(self.all_requests)
                self.all_requests.append(request_data)
                self._add_request_to_table(found_index, request_data)
                self.stats_label.setText("Captured: {} requests".format(len(self.all_requests)))
            
            request_indices.append(found_index)
        
        # Add to group
        if group_name not in self.groups:
            self.groups[group_name] = []
            self.group_colors[group_name] = self._get_next_color()
        
        for idx in request_indices:
            if idx not in self.groups[group_name]:
                self.groups[group_name].append(idx)
        
        # Refresh groups view
        SwingUtilities.invokeLater(lambda: self._refresh_groups_view(None))
        
        print("Added {} requests to group '{}'".format(len(request_indices), group_name))
    
    def _delete_group(self, group_name):
        """Delete a group"""
        if group_name in self.groups:
            del self.groups[group_name]
            del self.group_colors[group_name]
            self._refresh_groups_view(None)
            print("Deleted group '{}'".format(group_name))


class BurpContextMenuListener(ActionListener):
    """Listener for Burp's context menu (Proxy, Repeater, etc.)"""
    
    def __init__(self, extender, selected_messages, group_name):
        self.extender = extender
        self.selected_messages = selected_messages
        self.group_name = group_name
    
    def actionPerformed(self, event):
        self.extender.add_requests_from_burp_context(self.selected_messages, self.group_name)


class TableMouseListener(MouseAdapter):
    """Handle right-click on requests table"""
    
    def __init__(self, extender):
        self.extender = extender
    
    def mousePressed(self, event):
        self._show_popup(event)
    
    def mouseReleased(self, event):
        self._show_popup(event)
    
    def _show_popup(self, event):
        if not event.isPopupTrigger():
            return
        
        # Get selected rows
        selected_rows = self.extender.requests_table.getSelectedRows()
        
        if not selected_rows or len(selected_rows) == 0:
            return
        
        # Create popup menu
        popup = JPopupMenu()
        
        # Add "Create New Group" option
        new_group_item = JMenuItem("Create New Group")
        new_group_item.addActionListener(CreateGroupMenuListener(self.extender, selected_rows))
        popup.add(new_group_item)
        
        # Add separator if there are existing groups
        if self.extender.groups:
            popup.addSeparator()
            
            # Add menu items for each existing group
            for group_name in sorted(self.extender.groups.keys()):
                item = JMenuItem("Add to '{}'".format(group_name))
                item.addActionListener(AddToGroupListener(self.extender, selected_rows, group_name))
                popup.add(item)
        
        # Show popup at mouse location
        popup.show(event.getComponent(), event.getX(), event.getY())


class CreateGroupMenuListener(ActionListener):
    """Listener for creating a new group"""
    
    def __init__(self, extender, selected_rows):
        self.extender = extender
        self.selected_rows = selected_rows
    
    def actionPerformed(self, event):
        from javax.swing import JOptionPane
        
        group_name = JOptionPane.showInputDialog(
            None,
            "Enter group name:",
            "Create New Group",
            JOptionPane.PLAIN_MESSAGE
        )
        
        if group_name:
            self.extender.create_new_group(self.selected_rows, group_name)


class AddToGroupListener(ActionListener):
    """Listener for adding to existing group"""
    
    def __init__(self, extender, selected_rows, group_name):
        self.extender = extender
        self.selected_rows = selected_rows
        self.group_name = group_name
    
    def actionPerformed(self, event):
        self.extender.add_to_existing_group(self.selected_rows, self.group_name)
