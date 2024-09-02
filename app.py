import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QRadioButton, QLineEdit, QTextEdit, QPushButton, QButtonGroup, QComboBox

class ScannerApp(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()

        # Tool Selection Section
        tool_label = QLabel("Select Tool:")
        main_layout.addWidget(tool_label)

        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["Nmap", "Wireshark", "Metasploit", "Nessus", "Aircrack-ng", "Burp Suite", "Nikto", "Hydra", "John the Ripper", "OpenVAS", "SQLmap", "Snort", "DirBuster"])
        self.tool_combo.currentIndexChanged.connect(self.update_scan_options)
        main_layout.addWidget(self.tool_combo)

        # Scan Options Section
        self.scan_options = []

        self.ip_entry = QLineEdit()
        main_layout.addWidget(self.ip_entry)

        self.arg_entry = QLineEdit()
        main_layout.addWidget(self.arg_entry)

        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        main_layout.addWidget(self.output_display)

        scan_button = QPushButton("Run Scan")
        scan_button.clicked.connect(self.run_scan)
        main_layout.addWidget(scan_button)

        clear_button = QPushButton("Clear Output")
        clear_button.clicked.connect(self.clear_output)
        main_layout.addWidget(clear_button)

        self.setLayout(main_layout)
        self.setWindowTitle("Resploit")
        self.setGeometry(600, 600, 1000, 1000)
        self.update_scan_options()

    def add_scan_option(self, name, command):
        btn = QRadioButton(name)
        btn.command = command
        self.scan_options.append(btn)
        self.layout().insertWidget(self.layout().indexOf(self.ip_entry) + 1, btn)

    def update_scan_options(self):
        for btn in self.scan_options:
            btn.setParent(None)
        self.scan_options.clear()

        tool = self.tool_combo.currentText()
        if tool == "Nmap":
            self.add_scan_option("Quick Scan", "nmap -T4 -F")
            self.add_scan_option("Intense Scan", "nmap -T4 -A -v")
            self.add_scan_option("Ping Scan", "nmap -sn")
            self.add_scan_option("Version Detection", "nmap -sV")
            self.add_scan_option("OS Detection", "nmap -O")
        elif tool == "Nikto":
            self.add_scan_option("Basic Scan", "nikto -h")
            self.add_scan_option("Full Scan", "nikto -h -Tuning x")
            self.add_scan_option("SSL Scan", "nikto -h -ssl")
            self.add_scan_option("Mutate Scan", "nikto -h -mutate 2")
            self.add_scan_option("Database Injection Scan", "nikto -h -Tuning 9")
            self.add_scan_option("XSS Scan", "nikto -h -Tuning 4")
        elif tool == "DirBuster":
            self.add_scan_option("Basic Scan", "dirb")
        elif tool == "Wireshark":
            self.add_scan_option("Capture Traffic", "wireshark -i eth0")
        elif tool == "Metasploit":
            self.add_scan_option("Start Metasploit", "msfconsole")
        elif tool == "Nessus":
            self.add_scan_option("Launch Nessus Scan", "nessus -q")
        elif tool == "Aircrack-ng":
            self.add_scan_option("Start Aircrack-ng", "aircrack-ng")
        elif tool == "Hydra":
            self.add_scan_option("Password Cracking", "hydra -l username -P passlist.txt ftp://target")
        elif tool == "John the Ripper":
            self.add_scan_option("Basic Password Crack", "john --wordlist=password.lst hashfile")
        elif tool == "OpenVAS":
            self.add_scan_option("Start OpenVAS", "openvas-start")
        elif tool == "SQLmap":
            self.add_scan_option("SQL Injection Scan", "sqlmap -u http://target.com/vulnerable.php")
        elif tool == "Snort":
            self.add_scan_option("Run Snort", "snort -A console -q -c /etc/snort/snort.conf -i eth0")

    def run_scan(self):
        selected_scan = next((btn for btn in self.scan_options if btn.isChecked()), None)
        if not selected_scan:
            self.output_display.append("Please select a scan option.\n")
            return

        ip_address = self.ip_entry.text().strip()
        arguments = self.arg_entry.text().strip()
        command = f"{selected_scan.command} {arguments} {ip_address}"

        self.output_display.append(f"Running command: {command}\n")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            self.output_display.append(result.stdout + "\n")
            self.output_display.append(result.stderr + "\n")
        except Exception as e:
            self.output_display.append(f"Error: {str(e)}\n")

    def clear_output(self):
        self.output_display.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ScannerApp()
    ex.show()
    sys.exit(app.exec_())