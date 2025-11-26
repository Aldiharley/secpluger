"""
SecPluger Main GUI
Simple tkinter interface for workflow management
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from engine.workflow_engine import WorkflowEngine


class SecPlugerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecPluger - Pentesting Workflow Automation")
        self.root.geometry("1200x800")

        self.engine = WorkflowEngine()
        self.current_workflow_path = None

        self.setup_ui()

    def setup_ui(self):
        """Set up the main UI"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Workflow", command=self.new_workflow)
        file_menu.add_command(label="Open Workflow", command=self.open_workflow)
        file_menu.add_command(label="Save Workflow", command=self.save_workflow)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Title
        title = ttk.Label(main_frame, text="SecPluger - Workflow Automation", font=('Arial', 16, 'bold'))
        title.grid(row=0, column=0, columnspan=2, pady=10)

        # Left panel - Workflow nodes
        left_panel = ttk.LabelFrame(main_frame, text="Workflow Nodes", padding="10")
        left_panel.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))

        # Node list
        self.node_listbox = tk.Listbox(left_panel, width=30, height=20)
        self.node_listbox.pack(fill=tk.BOTH, expand=True)
        self.node_listbox.bind('<<ListboxSelect>>', self.on_node_select)

        # Node buttons
        node_btn_frame = ttk.Frame(left_panel)
        node_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(node_btn_frame, text="Add Node", command=self.add_node).pack(side=tk.LEFT, padx=2)
        ttk.Button(node_btn_frame, text="Remove Node", command=self.remove_node).pack(side=tk.LEFT, padx=2)

        # Right panel - Node configuration
        right_panel = ttk.LabelFrame(main_frame, text="Node Configuration", padding="10")
        right_panel.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Node type
        ttk.Label(right_panel, text="Node Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.node_type_var = tk.StringVar()
        node_type_combo = ttk.Combobox(right_panel, textvariable=self.node_type_var, width=30)
        node_type_combo['values'] = ('nmap', 'gobuster', 'sqlmap', 'nuclei', 'conditional', 'sleep')
        node_type_combo.grid(row=0, column=1, sticky=tk.W, pady=5)

        # Node data (JSON)
        ttk.Label(right_panel, text="Node Data (JSON):").grid(row=1, column=0, sticky=tk.NW, pady=5)
        self.node_data_text = scrolledtext.ScrolledText(right_panel, width=50, height=10)
        self.node_data_text.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

        # Update node button
        ttk.Button(right_panel, text="Update Node", command=self.update_node).grid(row=2, column=1, sticky=tk.W, pady=5)

        # Bottom panel - Execution
        exec_frame = ttk.LabelFrame(main_frame, text="Workflow Execution", padding="10")
        exec_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        # Target input
        ttk.Label(exec_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(exec_frame, textvariable=self.target_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=5)

        # Execute button
        ttk.Button(exec_frame, text="Execute Workflow", command=self.execute_workflow,
                  style='Accent.TButton').grid(row=0, column=2, padx=10)

        # Status label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(exec_frame, textvariable=self.status_var, foreground='blue').grid(row=0, column=3, padx=10)

        # Output panel
        output_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="10")
        output_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        self.output_text = scrolledtext.ScrolledText(output_frame, width=100, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Initialize empty workflow
        self.workflow = {"name": "New Workflow", "nodes": [], "edges": []}
        self.update_node_list()

    def new_workflow(self):
        """Create a new workflow"""
        self.workflow = {"name": "New Workflow", "nodes": [], "edges": []}
        self.current_workflow_path = None
        self.update_node_list()
        self.log("Created new workflow")

    def open_workflow(self):
        """Open existing workflow"""
        file_path = filedialog.askopenfilename(
            title="Open Workflow",
            initialdir="workflows",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if file_path:
            with open(file_path, 'r') as f:
                self.workflow = json.load(f)
            self.current_workflow_path = file_path
            self.update_node_list()
            self.log(f"Opened workflow: {file_path}")

    def save_workflow(self):
        """Save current workflow"""
        if not self.current_workflow_path:
            file_path = filedialog.asksaveasfilename(
                title="Save Workflow",
                initialdir="workflows",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not file_path:
                return
            self.current_workflow_path = file_path

        # Ensure workflows directory exists
        Path("workflows").mkdir(exist_ok=True)

        with open(self.current_workflow_path, 'w') as f:
            json.dump(self.workflow, f, indent=2)

        self.log(f"Saved workflow: {self.current_workflow_path}")

    def add_node(self):
        """Add a new node to workflow"""
        node_id = str(len(self.workflow['nodes']) + 1)
        new_node = {
            "id": node_id,
            "type": "nmap",
            "data": {"target": "{{TARGET}}", "scan_type": "quick"}
        }

        self.workflow['nodes'].append(new_node)

        # Auto-connect to previous node
        if len(self.workflow['nodes']) > 1:
            prev_id = str(len(self.workflow['nodes']) - 1)
            self.workflow['edges'].append({"from": prev_id, "to": node_id})

        self.update_node_list()
        self.log(f"Added node: {node_id}")

    def remove_node(self):
        """Remove selected node"""
        selection = self.node_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        node = self.workflow['nodes'][index]
        node_id = node['id']

        # Remove node
        self.workflow['nodes'].pop(index)

        # Remove edges connected to this node
        self.workflow['edges'] = [
            edge for edge in self.workflow['edges']
            if edge.get('from') != node_id and edge.get('to') != node_id
        ]

        self.update_node_list()
        self.log(f"Removed node: {node_id}")

    def on_node_select(self, event):
        """Handle node selection"""
        selection = self.node_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        node = self.workflow['nodes'][index]

        # Update UI with node data
        self.node_type_var.set(node.get('type', ''))
        self.node_data_text.delete('1.0', tk.END)
        self.node_data_text.insert('1.0', json.dumps(node.get('data', {}), indent=2))

    def update_node(self):
        """Update selected node with current configuration"""
        selection = self.node_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a node to update")
            return

        index = selection[0]
        node = self.workflow['nodes'][index]

        # Update type
        node['type'] = self.node_type_var.get()

        # Update data (parse JSON)
        try:
            node['data'] = json.loads(self.node_data_text.get('1.0', tk.END))
            self.update_node_list()
            self.log(f"Updated node: {node['id']}")
        except json.JSONDecodeError as e:
            messagebox.showerror("Invalid JSON", f"Error parsing node data: {e}")

    def update_node_list(self):
        """Refresh the node listbox"""
        self.node_listbox.delete(0, tk.END)
        for node in self.workflow['nodes']:
            self.node_listbox.insert(tk.END, f"{node['id']}: {node['type']}")

    def execute_workflow(self):
        """Execute the current workflow"""
        if not self.workflow['nodes']:
            messagebox.showwarning("Empty Workflow", "Please add nodes to the workflow first")
            return

        target = self.target_var.get()
        if not target:
            messagebox.showwarning("No Target", "Please enter a target")
            return

        self.log(f"Executing workflow with target: {target}")
        self.status_var.set("Running...")
        self.root.update()

        try:
            # Save workflow temporarily
            temp_workflow = Path("workflows/temp_workflow.json")
            temp_workflow.parent.mkdir(exist_ok=True)
            with open(temp_workflow, 'w') as f:
                json.dump(self.workflow, f)

            # Execute
            self.engine.load_workflow(str(temp_workflow))
            result = self.engine.execute(target=target)

            self.log(f"Execution completed: {result['execution_id']}")
            self.log(f"Evidence saved to: {result['evidence_path']}")
            self.log(f"Nodes completed: {result['nodes_completed']}/{len(self.workflow['nodes'])}")

            self.status_var.set("Completed")

            messagebox.showinfo("Execution Complete",
                              f"Workflow executed successfully!\n\n"
                              f"Evidence: {result['evidence_path']}\n"
                              f"Nodes completed: {result['nodes_completed']}")

        except Exception as e:
            self.log(f"ERROR: {e}")
            self.status_var.set("Failed")
            messagebox.showerror("Execution Error", f"Error executing workflow:\n{e}")

    def log(self, message: str):
        """Add message to output log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.output_text.see(tk.END)
        self.root.update()


def main():
    root = tk.Tk()
    app = SecPlugerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
