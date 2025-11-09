from burp import IBurpExtender, ITab
from javax.swing import (JPanel, JButton, JScrollPane, JTable, JLabel,
                         JSplitPane, BorderFactory, BoxLayout, JTextArea,
                         JOptionPane, JFileChooser)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, GridLayout, Color, Dimension, Font
from java.awt.event import ActionListener
import re
import json
from collections import defaultdict
from urllib.parse import urlparse

class BurpExtender(IBurpExtender, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Authorization Testing")
        
        # Data storage - using sets for discrete math operations
        self.lower_auth_requests = {}  # {index: request_data}
        self.higher_auth_requests = {}  # {index: request_data}
        self.lower_auth_indexes = set()  # Set of selected indexes
        self.higher_auth_indexes = set()  # Set of selected indexes
        
        # Analysis results
        self.shared_endpoints = []  # Intersection results
        self.unique_lower = set()  # Lower - Higher
        self.unique_higher = set()  # Higher - Lower
        self.empty_intersections = []  # Critical findings
        
        # Create UI
        self._create_ui()
        
        callbacks.addSuiteTab(self)
        
        print("="*70)
        print("Authorization Testing Extension Loaded")
        print("="*70)
        print("Instructions:")
        print("1. Select requests in HTTP History")
        print("2. Click 'Add to LOW AUTH' or 'Add to HIGH AUTH'")
        print("3. Review your selections in the tables")
        print("4. Click 'Generate Wordlists' to perform set analysis")
        print("="*70)
    
    def _create_ui(self):
        """Create the main UI"""
        self._main_panel = JPanel(BorderLayout())
        
        # Top panel - Instructions and controls
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        top_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Instructions
        instructions = JLabel("<html><b>Authorization Testing - Set Theory Based</b><br>" +
                            "Select requests in HTTP History, then add them to LOW or HIGH auth datasets</html>")
        instructions.setFont(Font("Dialog", Font.BOLD, 12))
        top_panel.add(instructions)
        
        # Button panel
        button_panel = JPanel(GridLayout(1, 4, 10, 10))
        button_panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0))
        
        self.add_lower_button = JButton("Add to LOW AUTH", actionPerformed=self.add_to_lower)
        self.add_higher_button = JButton("Add to HIGH AUTH", actionPerformed=self.add_to_higher)
        self.clear_button = JButton("Clear All", actionPerformed=self.clear_all)
        self.generate_button = JButton("Generate Wordlists", actionPerformed=self.generate_wordlists)
        self.generate_button.setEnabled(False)
        
        button_panel.add(self.add_lower_button)
        button_panel.add(self.add_higher_button)
        button_panel.add(self.clear_button)
        button_panel.add(self.generate_button)
        
        top_panel.add(button_panel)
        
        # Statistics panel
        stats_panel = JPanel(GridLayout(1, 2, 10, 10))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Dataset Statistics"))
        
        self.lower_stats_label = JLabel("LOW AUTH: 0 requests")
        self.higher_stats_label = JLabel("HIGH AUTH: 0 requests")
        
        stats_panel.add(self.lower_stats_label)
        stats_panel.add(self.higher_stats_label)
        
        top_panel.add(stats_panel)
        
        # Middle panel - Split view of LOW and HIGH tables
        middle_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        middle_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # LOW AUTH table
        lower_panel = JPanel(BorderLayout())
        lower_panel.setBorder(BorderFactory.createTitledBorder("LOW AUTH Dataset"))
        
        self.lower_table_model = DefaultTableModel(["Index", "Method", "URL", "Cookies"], 0)
        self.lower_table = JTable(self.lower_table_model)
        self.lower_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        lower_scroll = JScrollPane(self.lower_table)
        
        lower_button_panel = JPanel(GridLayout(1, 1))
        self.remove_lower_button = JButton("Remove Selected", actionPerformed=self.remove_from_lower)
        lower_button_panel.add(self.remove_lower_button)
        
        lower_panel.add(lower_scroll, BorderLayout.CENTER)
        lower_panel.add(lower_button_panel, BorderLayout.SOUTH)
        
        # HIGH AUTH table
        higher_panel = JPanel(BorderLayout())
        higher_panel.setBorder(BorderFactory.createTitledBorder("HIGH AUTH Dataset"))
        
        self.higher_table_model = DefaultTableModel(["Index", "Method", "URL", "Cookies"], 0)
        self.higher_table = JTable(self.higher_table_model)
        self.higher_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        higher_scroll = JScrollPane(self.higher_table)
        
        higher_button_panel = JPanel(GridLayout(1, 1))
        self.remove_higher_button = JButton("Remove Selected", actionPerformed=self.remove_from_higher)
        higher_button_panel.add(self.remove_higher_button)
        
        higher_panel.add(higher_scroll, BorderLayout.CENTER)
        higher_panel.add(higher_button_panel, BorderLayout.SOUTH)
        
        middle_panel.setLeftComponent(lower_panel)
        middle_panel.setRightComponent(higher_panel)
        middle_panel.setDividerLocation(400)
        
        # Bottom panel - Analysis results
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.setBorder(BorderFactory.createTitledBorder("Analysis Results"))
        
        self.results_text = JTextArea()
        self.results_text.setEditable(False)
        self.results_text.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.results_text.setText("Select requests and click 'Generate Wordlists' to see analysis...")
        results_scroll = JScrollPane(self.results_text)
        
        bottom_panel.add(results_scroll, BorderLayout.CENTER)
        
        # Export button
        export_panel = JPanel()
        self.export_button = JButton("Export to Directory", actionPerformed=self.export_to_directory)
        self.export_button.setEnabled(False)
        export_panel.add(self.export_button)
        bottom_panel.add(export_panel, BorderLayout.SOUTH)
        
        # Assemble main panel
        split_main = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_main.setTopComponent(middle_panel)
        split_main.setBottomComponent(bottom_panel)
        split_main.setDividerLocation(300)
        
        self._main_panel.add(top_panel, BorderLayout.NORTH)
        self._main_panel.add(split_main, BorderLayout.CENTER)
    
    def getTabCaption(self):
        return "Auth Testing"
    
    def getUiComponent(self):
        return self._main_panel
    
    def add_to_lower(self, event):
        """Add selected requests to LOW AUTH dataset"""
        self._add_to_dataset("LOW")
    
    def add_to_higher(self, event):
        """Add selected requests to HIGH AUTH dataset"""
        self._add_to_dataset("HIGH")
    
    def _add_to_dataset(self, dataset_type):
        """Generic method to add requests to a dataset"""
        selected_messages = self._callbacks.getSelectedMessages()
        
        if not selected_messages or len(selected_messages) == 0:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "No requests selected!\n\nSelect requests in HTTP History first.",
                "No Selection",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        added_count = 0
        
        for messageInfo in selected_messages:
            # Generate unique index
            index = hash(messageInfo) % 1000000
            
            # Extract request data
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            
            # Extract cookies
            cookies = self._extract_cookies(messageInfo)
            
            if not cookies:
                print("Skipping request (no cookies): {}".format(url))
                continue
            
            # Store request data
            request_data = {
                "index": index,
                "url": url,
                "method": method,
                "cookies": cookies,
                "messageInfo": messageInfo
            }
            
            # Add to appropriate dataset
            if dataset_type == "LOW":
                if index not in self.lower_auth_indexes:
                    self.lower_auth_requests[index] = request_data
                    self.lower_auth_indexes.add(index)
                    added_count += 1
            else:  # HIGH
                if index not in self.higher_auth_indexes:
                    self.higher_auth_requests[index] = request_data
                    self.higher_auth_indexes.add(index)
                    added_count += 1
        
        print("Added {} requests to {} AUTH".format(added_count, dataset_type))
        self._update_tables()
        self._update_statistics()
        
        # Enable generate button if we have both datasets
        if len(self.lower_auth_requests) > 0 and len(self.higher_auth_requests) > 0:
            self.generate_button.setEnabled(True)
    
    def _extract_cookies(self, messageInfo):
        """Extract cookies from request"""
        request = messageInfo.getRequest()
        request_str = request.tostring()
        
        cookies = {}
        cookie_matches = re.findall(r'^Cookie:\s*(.+)$', request_str, re.MULTILINE | re.IGNORECASE)
        
        for cookie_line in cookie_matches:
            cookie_line = cookie_line.rstrip('\r\n')
            cookie_pairs = cookie_line.split(';')
            
            for pair in cookie_pairs:
                pair = pair.strip()
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    cookies[name.strip()] = value.strip()
        
        return cookies
    
    def _update_tables(self):
        """Update both dataset tables"""
        # Clear tables
        self.lower_table_model.setRowCount(0)
        self.higher_table_model.setRowCount(0)
        
        # Populate LOW AUTH table
        for index in sorted(self.lower_auth_indexes):
            data = self.lower_auth_requests[index]
            cookies_str = ", ".join(data["cookies"].keys())
            url_short = data["url"][:50] + "..." if len(data["url"]) > 50 else data["url"]
            
            self.lower_table_model.addRow([
                str(index),
                data["method"],
                url_short,
                cookies_str
            ])
        
        # Populate HIGH AUTH table
        for index in sorted(self.higher_auth_indexes):
            data = self.higher_auth_requests[index]
            cookies_str = ", ".join(data["cookies"].keys())
            url_short = data["url"][:50] + "..." if len(data["url"]) > 50 else data["url"]
            
            self.higher_table_model.addRow([
                str(index),
                data["method"],
                url_short,
                cookies_str
            ])
    
    def _update_statistics(self):
        """Update statistics labels"""
        self.lower_stats_label.setText("LOW AUTH: {} requests".format(len(self.lower_auth_requests)))
        self.higher_stats_label.setText("HIGH AUTH: {} requests".format(len(self.higher_auth_requests)))
    
    def remove_from_lower(self, event):
        """Remove selected rows from LOW AUTH dataset"""
        self._remove_from_dataset("LOW")
    
    def remove_from_higher(self, event):
        """Remove selected rows from HIGH AUTH dataset"""
        self._remove_from_dataset("HIGH")
    
    def _remove_from_dataset(self, dataset_type):
        """Generic method to remove selected rows"""
        if dataset_type == "LOW":
            table = self.lower_table
            requests = self.lower_auth_requests
            indexes = self.lower_auth_indexes
        else:
            table = self.higher_table
            requests = self.higher_auth_requests
            indexes = self.higher_auth_indexes
        
        selected_rows = table.getSelectedRows()
        
        if len(selected_rows) == 0:
            return
        
        # Get indexes to remove
        indexes_to_remove = []
        for row in selected_rows:
            index_str = table.getValueAt(row, 0)
            indexes_to_remove.append(int(index_str))
        
        # Remove from dataset
        for index in indexes_to_remove:
            if index in requests:
                del requests[index]
            if index in indexes:
                indexes.remove(index)
        
        print("Removed {} requests from {} AUTH".format(len(indexes_to_remove), dataset_type))
        self._update_tables()
        self._update_statistics()
        
        # Disable generate if datasets empty
        if len(self.lower_auth_requests) == 0 or len(self.higher_auth_requests) == 0:
            self.generate_button.setEnabled(False)
    
    def clear_all(self, event):
        """Clear all datasets"""
        result = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Clear all datasets?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            self.lower_auth_requests.clear()
            self.higher_auth_requests.clear()
            self.lower_auth_indexes.clear()
            self.higher_auth_indexes.clear()
            
            self._update_tables()
            self._update_statistics()
            
            self.results_text.setText("Datasets cleared. Select requests to begin.")
            self.generate_button.setEnabled(False)
            self.export_button.setEnabled(False)
            
            print("All datasets cleared")
    
    def generate_wordlists(self, event):
        """Perform set analysis and generate wordlists"""
        print("\n" + "="*70)
        print("PERFORMING SET ANALYSIS")
        print("="*70)
        
        self.results_text.setText("Analyzing datasets...\n\n")
        
        # Find matching endpoints (intersection operation)
        self.shared_endpoints = []
        self.empty_intersections = []
        
        matched_lower = set()
        matched_higher = set()
        
        print("Finding endpoint matches...")
        
        for lower_idx, lower_data in self.lower_auth_requests.items():
            for higher_idx, higher_data in self.higher_auth_requests.items():
                if higher_idx in matched_higher:
                    continue
                
                # Check if endpoints match
                if self._endpoints_match(lower_data["url"], higher_data["url"]):
                    matched_lower.add(lower_idx)
                    matched_higher.add(higher_idx)
                    
                    # Analyze cookie intersection
                    lower_cookies = set(lower_data["cookies"].keys())
                    higher_cookies = set(higher_data["cookies"].keys())
                    
                    shared_cookies = lower_cookies & higher_cookies  # Intersection
                    
                    if len(shared_cookies) == 0:
                        # CRITICAL: Empty intersection!
                        self.empty_intersections.append({
                            "lower_idx": lower_idx,
                            "higher_idx": higher_idx,
                            "lower_data": lower_data,
                            "higher_data": higher_data
                        })
                    else:
                        # Normal shared endpoint
                        self.shared_endpoints.append({
                            "lower_idx": lower_idx,
                            "higher_idx": higher_idx,
                            "lower_data": lower_data,
                            "higher_data": higher_data,
                            "shared_cookies": shared_cookies
                        })
        
        # Find unique endpoints (set difference operations)
        self.unique_lower = self.lower_auth_indexes - matched_lower  # A - B
        self.unique_higher = self.higher_auth_indexes - matched_higher  # B - A
        
        print("Matches found: {}".format(len(self.shared_endpoints)))
        print("Empty intersections: {}".format(len(self.empty_intersections)))
        print("Unique to LOW: {}".format(len(self.unique_lower)))
        print("Unique to HIGH: {}".format(len(self.unique_higher)))
        
        # Display results
        self._display_results()
        
        # Enable export
        self.export_button.setEnabled(True)
        
        print("="*70 + "\n")
    
    def _endpoints_match(self, url1, url2):
        """Check if two URLs represent the same endpoint"""
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        # Must match scheme and host
        if parsed1.scheme != parsed2.scheme or parsed1.netloc != parsed2.netloc:
            return False
        
        # Normalize paths (replace IDs with placeholders)
        path1 = self._normalize_path(parsed1.path)
        path2 = self._normalize_path(parsed2.path)
        
        return path1 == path2
    
    def _normalize_path(self, path):
        """Normalize path by replacing IDs"""
        segments = [s for s in path.split('/') if s]
        normalized = []
        
        for segment in segments:
            # Replace numeric IDs
            if re.match(r'^\d{2,}$', segment):
                normalized.append('{ID}')
            # Replace UUIDs
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment, re.IGNORECASE):
                normalized.append('{UUID}')
            else:
                normalized.append(segment)
        
        return '/'.join(normalized)
    
    def _display_results(self):
        """Display analysis results"""
        results = []
        
        results.append("="*70)
        results.append("SET ANALYSIS RESULTS")
        results.append("="*70)
        results.append("")
        
        # Statistics
        results.append("DATASETS:")
        results.append("  LOW AUTH:  {} requests".format(len(self.lower_auth_requests)))
        results.append("  HIGH AUTH: {} requests".format(len(self.higher_auth_requests)))
        results.append("")
        
        # Set operations results
        results.append("SET OPERATIONS:")
        results.append("  Shared Endpoints (Intersection):      {}".format(len(self.shared_endpoints)))
        
        if len(self.empty_intersections) > 0:
            results.append("  ** CRITICAL: Empty Intersections:      {}".format(len(self.empty_intersections)))
        
        results.append("  Unique to LOW (A - B):                 {}".format(len(self.unique_lower)))
        results.append("  Unique to HIGH (B - A):                {}".format(len(self.unique_higher)))
        results.append("")
        
        # Critical findings
        if len(self.empty_intersections) > 0:
            results.append("** CRITICAL SECURITY FINDINGS **")
            results.append("-"*70)
            results.append("Found {} endpoints with EMPTY COOKIE INTERSECTION!".format(len(self.empty_intersections)))
            results.append("Same endpoint accessed by both users but NO shared cookies.")
            results.append("High risk of authorization bypass!")
            results.append("")
            
            for i, match in enumerate(self.empty_intersections[:5], 1):
                results.append("  {}. LOW[{}] <-> HIGH[{}]".format(
                    i,
                    match["lower_idx"],
                    match["higher_idx"]
                ))
                results.append("     URL: {}".format(match["lower_data"]["url"][:60]))
                results.append("     LOW cookies:  {}".format(", ".join(match["lower_data"]["cookies"].keys())))
                results.append("     HIGH cookies: {}".format(", ".join(match["higher_data"]["cookies"].keys())))
                results.append("")
            
            if len(self.empty_intersections) > 5:
                results.append("  ... and {} more".format(len(self.empty_intersections) - 5))
                results.append("")
        
        # Wordlist generation summary
        results.append("WORDLIST GENERATION:")
        results.append("-"*70)
        results.append("")
        results.append("For Shared Endpoints:")
        results.append("  - Test_Lower wordlist: HIGH auth cookie values (for escalation)")
        results.append("  - Test_Higher wordlist: LOW auth cookie values (for downgrade)")
        results.append("")
        results.append("For Unique HIGH endpoints:")
        results.append("  - Test_Lower wordlist: All LOW auth values (unauthorized access)")
        results.append("")
        results.append("For Unique LOW endpoints:")
        results.append("  - Test_Higher wordlist: All HIGH auth values (improper access)")
        results.append("")
        
        if len(self.empty_intersections) > 0:
            results.append("For Empty Intersections (CRITICAL):")
            results.append("  - wordlist_all_cookies.txt: Union of ALL cookies from both")
            results.append("  - wordlist_unique_values.txt: Unique cookie values only")
            results.append("")
        
        results.append("Click 'Export to Directory' to save wordlists to disk.")
        results.append("="*70)
        
        self.results_text.setText("\n".join(results))
    
    def export_to_directory(self, event):
        """Export wordlists to directory structure"""
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setDialogTitle("Select Export Directory")
        
        ret = chooser.showSaveDialog(self._main_panel)
        
        if ret == JFileChooser.APPROVE_OPTION:
            base_dir = chooser.getSelectedFile().getAbsolutePath()
            self._export_wordlists(base_dir)
    
    def _export_wordlists(self, base_dir):
        """Actually export the wordlists"""
        import os
        
        try:
            # Create base directory
            auth_testing_dir = os.path.join(base_dir, "Authorization-Testing")
            
            if not os.path.exists(auth_testing_dir):
                os.makedirs(auth_testing_dir)
            
            print("\nExporting wordlists to: {}".format(auth_testing_dir))
            
            # Export shared endpoints
            if len(self.shared_endpoints) > 0:
                shared_dir = os.path.join(auth_testing_dir, "Shared")
                os.makedirs(shared_dir, exist_ok=True)
                
                for match in self.shared_endpoints:
                    self._export_shared_match(shared_dir, match)
            
            # Export empty intersections
            if len(self.empty_intersections) > 0:
                empty_dir = os.path.join(auth_testing_dir, "EmptyIntersection")
                os.makedirs(empty_dir, exist_ok=True)
                
                for match in self.empty_intersections:
                    self._export_empty_intersection(empty_dir, match)
            
            # Export unique HIGH
            if len(self.unique_higher) > 0:
                u_higher_dir = os.path.join(auth_testing_dir, "U_Higher")
                os.makedirs(u_higher_dir, exist_ok=True)
                
                self._export_unique_higher(u_higher_dir)
            
            # Export unique LOW
            if len(self.unique_lower) > 0:
                u_lower_dir = os.path.join(auth_testing_dir, "U_Lower")
                os.makedirs(u_lower_dir, exist_ok=True)
                
                self._export_unique_lower(u_lower_dir)
            
            # Create README
            self._create_readme(auth_testing_dir)
            
            print("Export complete!")
            
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Wordlists exported successfully to:\n{}".format(auth_testing_dir),
                "Export Complete",
                JOptionPane.INFORMATION_MESSAGE
            )
            
        except Exception as e:
            print("Error exporting: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error exporting wordlists:\n{}".format(str(e)),
                "Export Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _export_shared_match(self, base_dir, match):
        """Export wordlists for a shared endpoint match"""
        import os
        
        lower_idx = match["lower_idx"]
        higher_idx = match["higher_idx"]
        lower_data = match["lower_data"]
        higher_data = match["higher_data"]
        shared_cookies = match["shared_cookies"]
        
        # Create match directory
        match_dir = os.path.join(base_dir, "H{}_L{}".format(higher_idx, lower_idx))
        os.makedirs(match_dir, exist_ok=True)
        
        # Test_Lower: HIGH auth values for escalation
        test_lower_dir = os.path.join(match_dir, "Test_Lower")
        os.makedirs(test_lower_dir, exist_ok=True)
        
        escalation_values = set()
        for cookie_name in shared_cookies:
            escalation_values.add(higher_data["cookies"][cookie_name])
        
        with open(os.path.join(test_lower_dir, "wordlist.txt"), 'w') as f:
            for value in sorted(escalation_values):
                f.write("{}\n".format(value))
        
        # Test_Higher: LOW auth values for downgrade
        test_higher_dir = os.path.join(match_dir, "Test_Higher")
        os.makedirs(test_higher_dir, exist_ok=True)
        
        downgrade_values = set()
        for cookie_name in shared_cookies:
            downgrade_values.add(lower_data["cookies"][cookie_name])
        
        with open(os.path.join(test_higher_dir, "wordlist.txt"), 'w') as f:
            for value in sorted(downgrade_values):
                f.write("{}\n".format(value))
        
        # Info JSON
        info = {
            "lower_index": lower_idx,
            "higher_index": higher_idx,
            "lower_url": lower_data["url"],
            "higher_url": higher_data["url"],
            "shared_cookies": list(shared_cookies)
        }
        
        with open(os.path.join(match_dir, "match_info.json"), 'w') as f:
            json.dump(info, f, indent=2)
    
    def _export_empty_intersection(self, base_dir, match):
        """Export wordlists for empty intersection (CRITICAL)"""
        import os
        
        lower_idx = match["lower_idx"]
        higher_idx = match["higher_idx"]
        lower_data = match["lower_data"]
        higher_data = match["higher_data"]
        
        # Create directory
        match_dir = os.path.join(base_dir, "H{}_L{}_EMPTY".format(higher_idx, lower_idx))
        os.makedirs(match_dir, exist_ok=True)
        
        # Union wordlist (all cookies)
        all_cookies = set()
        
        for cookie_name, cookie_value in lower_data["cookies"].items():
            all_cookies.add(cookie_value)
            all_cookies.add("{}={}".format(cookie_name, cookie_value))
        
        for cookie_name, cookie_value in higher_data["cookies"].items():
            all_cookies.add(cookie_value)
            all_cookies.add("{}={}".format(cookie_name, cookie_value))
        
        with open(os.path.join(match_dir, "wordlist_all_cookies.txt"), 'w') as f:
            for value in sorted(all_cookies):
                f.write("{}\n".format(value))
        
        # Warning file
        with open(os.path.join(match_dir, "CRITICAL_WARNING.txt"), 'w') as f:
            f.write("CRITICAL: Empty Cookie Intersection\n")
            f.write("="*60 + "\n\n")
            f.write("Same endpoint, NO shared cookies!\n")
            f.write("High risk of authorization bypass.\n\n")
            f.write("URL: {}\n".format(lower_data["url"]))
            f.write("LOW cookies:  {}\n".format(", ".join(lower_data["cookies"].keys())))
            f.write("HIGH cookies: {}\n".format(", ".join(higher_data["cookies"].keys())))
    
    def _export_unique_higher(self, base_dir):
        """Export wordlists for unique HIGH endpoints"""
        import os
        
        # Collect all LOW auth cookie values (union)
        all_lower_values = set()
        
        for idx, data in self.lower_auth_requests.items():
            for cookie_value in data["cookies"].values():
                all_lower_values.add(cookie_value)
        
        # Create wordlist for each unique HIGH endpoint
        for higher_idx in self.unique_higher:
            idx_dir = os.path.join(base_dir, "H{}".format(higher_idx))
            test_lower_dir = os.path.join(idx_dir, "Test_Lower")
            os.makedirs(test_lower_dir, exist_ok=True)
            
            with open(os.path.join(test_lower_dir, "wordlist.txt"), 'w') as f:
                for value in sorted(all_lower_values):
                    f.write("{}\n".format(value))
            
            # Info JSON
            higher_data = self.higher_auth_requests[higher_idx]
            info = {
                "index": higher_idx,
                "url": higher_data["url"],
                "method": higher_data["method"],
                "test_purpose": "Test unauthorized access with LOW auth cookies"
            }
            
            with open(os.path.join(idx_dir, "endpoint_info.json"), 'w') as f:
                json.dump(info, f, indent=2)
    
    def _export_unique_lower(self, base_dir):
        """Export wordlists for unique LOW endpoints"""
        import os
        
        # Collect all HIGH auth cookie values (union)
        all_higher_values = set()
        
        for idx, data in self.higher_auth_requests.items():
            for cookie_value in data["cookies"].values():
                all_higher_values.add(cookie_value)
        
        # Create wordlist for each unique LOW endpoint
        for lower_idx in self.unique_lower:
            idx_dir = os.path.join(base_dir, "L{}".format(lower_idx))
            test_higher_dir = os.path.join(idx_dir, "Test_Higher")
            os.makedirs(test_higher_dir, exist_ok=True)
            
            with open(os.path.join(test_higher_dir, "wordlist.txt"), 'w') as f:
                for value in sorted(all_higher_values):
                    f.write("{}\n".format(value))
            
            # Info JSON
            lower_data = self.lower_auth_requests[lower_idx]
            info = {
                "index": lower_idx,
                "url": lower_data["url"],
                "method": lower_data["method"],
                "test_purpose": "Test improper access with HIGH auth cookies"
            }
            
            with open(os.path.join(idx_dir, "endpoint_info.json"), 'w') as f:
                json.dump(info, f, indent=2)
    
    def _create_readme(self, base_dir):
        """Create main README file"""
        import os
        
        with open(os.path.join(base_dir, "README.md"), 'w') as f:
            f.write("# Authorization Testing - Set Theory Analysis\n\n")
            f.write("Generated from Burp Suite Extension\n\n")
            f.write("## Datasets\n\n")
            f.write("- LOW AUTH:  {} requests\n".format(len(self.lower_auth_requests)))
            f.write("- HIGH AUTH: {} requests\n\n".format(len(self.higher_auth_requests)))
            f.write("## Set Operations Results\n\n")
            f.write("- Shared Endpoints (Intersection): {}\n".format(len(self.shared_endpoints)))
            
            if len(self.empty_intersections) > 0:
                f.write("- **CRITICAL: Empty Intersections: {}**\n".format(len(self.empty_intersections)))
            
            f.write("- Unique to LOW (A - B): {}\n".format(len(self.unique_lower)))
            f.write("- Unique to HIGH (B - A): {}\n\n".format(len(self.unique_higher)))
            
            f.write("## Directory Structure\n\n")
            f.write("- `Shared/` - Matched endpoints between LOW and HIGH\n")
            
            if len(self.empty_intersections) > 0:
                f.write("- `EmptyIntersection/` - **CRITICAL** - Same endpoint, no shared cookies\n")
            
            f.write("- `U_Higher/` - Endpoints unique to HIGH auth (test with LOW)\n")
            f.write("- `U_Lower/` - Endpoints unique to LOW auth (test with HIGH)\n\n")
            f.write("## Usage\n\n")
            f.write("1. Navigate to test directories\n")
            f.write("2. Use `wordlist.txt` with Burp Intruder on cookie values\n")
            f.write("3. Check JSON files for endpoint details\n")


# Need this for file operations
from java.io import File
import os
