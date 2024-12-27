import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QTableWidget,
    QHeaderView,
    QTableWidgetItem,   
    QDialog,
    QMessageBox,
    QTabWidget,
    QComboBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import threading
from dns_resolver import resolve
from scapy.all import sniff, IP
import socket

class PacketDetailsDialog(QDialog):
    def __init__(self, packet_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.setFixedSize(400, 300)

        layout = QVBoxLayout(self)

        packet_details = QTextEdit(self)
        packet_details.setReadOnly(True)
        packet_details.setText(packet_data)
        layout.addWidget(packet_details)

        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)


class DNSResolverApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DNS Resolver Simulator")
        self.setStyleSheet(
            """
            QWidget {
                background-color: #1e1e1e;
            }
            QPushButton {
                background-color: #4caf50;
                color: white;
                border: 2px solid #388e3c;
                border-radius: 8px;
                padding: 10px 15px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
                border-color: #2e7d32;
            }
            QLineEdit, QComboBox {
                border: 2px solid #5d5d5d;
                border-radius: 8px;
                padding: 8px;
                font-size: 15px;
                font-family: Arial, sans-serif;
                color: white;
                background-color: #2c2c2c;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #4caf50; 
            }
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
            }
            QTreeWidget {
                background-color: #2c2c2c;
                border: 2px solid #5d5d5d;
                border-radius: 8px;
                color: #ffffff;
                font-size: 14px;
                padding: 5px;
            }
            QTextEdit {
                background-color: #0d0d0d;
                color: #00ff00;
                font-family: Consolas, monospace;
                font-size: 15px;
                border: 2px solid #5d5d5d;
                border-radius: 8px;
                padding: 10px;
            }
            QTextEdit:focus {
                border: 2px solid #4caf50;
            }
            QTableWidget {
                background-color: #2c2c2c;
                border: 2px solid #5d5d5d;
                border-radius: 8px;
                color: #ffffff;
                font-size: 14px;
                padding: 5px;
                selection-background-color: #4caf50;
            }
        """
        )
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Title
        title_label = QLabel("DNS Resolver Simulator")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        subtitle_label = QLabel("Project by Muhammad Jilani and Rizwan Yaqoob")
        subtitle_label.setFont(QFont("Arial", 12))
        subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle_label)

        # Input layout for domain
        input_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain name...")
        self.domain_input.setFont(QFont("Arial", 14))
        input_layout.addWidget(self.domain_input)

        # Dropdown for Query Type
        self.query_type_dropdown = QComboBox()
        self.query_type_dropdown.addItems(
            ["A", "AAAA", "MX", "CNAME", "PTR (Reverse DNS)"]
        )
        self.query_type_dropdown.setFont(QFont("Arial", 14))
        input_layout.addWidget(self.query_type_dropdown)

        # Dropdown for Resolution Method
        self.method_dropdown = QComboBox()
        self.method_dropdown.addItems(["Recursive", "Iterative"])
        self.method_dropdown.setFont(QFont("Arial", 14))
        input_layout.addWidget(self.method_dropdown)

        # Resolve Button
        resolve_button = QPushButton("Resolve DNS")
        resolve_button.clicked.connect(self.resolve_domain)
        input_layout.addWidget(resolve_button)
        layout.addLayout(input_layout)

        # Query History Table
        self.query_history_table = QTableWidget()
        self.query_history_table.setColumnCount(3)
        self.query_history_table.setHorizontalHeaderLabels(
            ["Domain", "Query Type", "Result"]
        )
        self.query_history_table.setSortingEnabled(True)
        self.query_history_table.verticalHeader().setVisible(False)
        self.query_history_table.hide()  # Initially hide the table
        layout.addWidget(self.query_history_table)

        # Show/Hide History Button
        self.show_history_button = QPushButton("Show Query History")
        self.show_history_button.clicked.connect(self.toggle_history_table)
        layout.addWidget(self.show_history_button)

        # Export Buttons
        export_layout = QHBoxLayout()
        self.export_csv_button = QPushButton("Export to CSV")
        self.export_csv_button.clicked.connect(self.export_to_csv)
        export_layout.addWidget(self.export_csv_button)

        self.export_json_button = QPushButton("Export to JSON")
        self.export_json_button.clicked.connect(self.export_to_json)
        export_layout.addWidget(self.export_json_button)
        layout.addLayout(export_layout)

        # Resolution Steps
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setText("Resolution Steps:")
        layout.addWidget(self.results_display)

        self.setLayout(layout)

    def resolve_domain(self):
        domain = self.domain_input.text()
        query_type = self.query_type_dropdown.currentText()
        method = self.method_dropdown.currentText().lower()

        if query_type == "PTR (Reverse DNS)":
            query_type = "PTR"
            domain = self.resolve_reverse_dns(domain)

        if not domain.strip():
            self.results_display.setText("Error: Please enter a valid domain name.")
            return

        self.results_display.setText("Initiating DNS Resolution...\n")

        try:
            results = resolve(domain, query_type, method)
            self.update_query_history_table(domain, query_type, results)
            self.results_display.append(
                f"Successfully resolved {domain} to {', '.join(results)}"
            )
        except Exception as e:
            self.results_display.append(f"Error: {str(e)}")

    def resolve_reverse_dns(self, ip_address):
        try:
            host = socket.gethostbyaddr(ip_address)[0]
            return host
        except socket.herror:
            return "No PTR record found"

    def update_query_history_table(self, domain, query_type, results):
        row_position = self.query_history_table.rowCount()
        self.query_history_table.insertRow(row_position)

        domain_item = QTableWidgetItem(domain)
        query_type_item = QTableWidgetItem(query_type)
        result_item = QTableWidgetItem(", ".join(results))

        self.query_history_table.setItem(row_position, 0, domain_item)
        self.query_history_table.setItem(row_position, 1, query_type_item)
        self.query_history_table.setItem(row_position, 2, result_item)

    def toggle_history_table(self):
        if self.query_history_table.isHidden():
            self.query_history_table.show()
            self.show_history_button.setText("Hide Query History")
        else:
            self.query_history_table.hide()
            self.show_history_button.setText("Show Query History")

    def export_to_csv(self):
        import csv

        try:
            with open("dns_query_history.csv", "w", newline="") as csv_file:
                fieldnames = ["Domain", "Query Type", "Result"]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()

                for row in range(self.query_history_table.rowCount()):
                    domain = self.query_history_table.item(row, 0).text()
                    query_type = self.query_history_table.item(row, 1).text()
                    result = self.query_history_table.item(row, 2).text()
                    writer.writerow(
                        {"Domain": domain, "Query Type": query_type, "Result": result}
                    )

            QMessageBox.information(
                self,
                "Export Successful",
                "Query history exported to dns_query_history.csv",
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting to CSV: {e}")

    def export_to_json(self):
        import json

        try:
            data = []
            for row in range(self.query_history_table.rowCount()):
                domain = self.query_history_table.item(row, 0).text()
                query_type = self.query_history_table.item(row, 1).text()
                result = self.query_history_table.item(row, 2).text()
                data.append(
                    {"Domain": domain, "Query Type": query_type, "Result": result}
                )

            with open("dns_query_history.json", "w") as json_file:
                json.dump(data, json_file, indent=4)

            QMessageBox.information(
                self,
                "Export Successful",
                "Query history exported to dns_query_history.json",
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting to JSON: {e}")

class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.packet_log_data = []  # Store captured packets
        self.capture_running = False

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Heading
        heading = QLabel("Packet Sniffer")
        heading.setFont(QFont("Arial", 24, QFont.Bold))
        heading.setAlignment(Qt.AlignCenter)
        layout.addWidget(heading)

        # Packet Log Table
        self.packet_log_table = QTableWidget(0, 7, self)
        self.packet_log_table.setHorizontalHeaderLabels([
            "Source IP", "Source Domain", "Dest IP", "Dest Domain", "Src Port", "Dst Port", "Protocol"
        ])
        header = self.packet_log_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)  # Make columns stretch

        # Style the headers
        self.packet_log_table.setStyleSheet("""
            QTableWidget {
                background-color: black;
                color: white;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #4caf50;
                color: white;
                font-weight: bold;
                border: 1px solid #ddd;
            }
        """)
        layout.addWidget(self.packet_log_table)

        # Buttons
        button_layout = QHBoxLayout()

        capture_button = QPushButton("Start Capture", self)
        capture_button.clicked.connect(self.start_capture)
        capture_button.setStyleSheet("""
            background-color: #4caf50;
            color: white;
            font-size: 14px;
            padding: 10px 20px;
            border-radius: 5px;
            border: none;
        """)
        button_layout.addWidget(capture_button)

        stop_button = QPushButton("Stop Capture", self)
        stop_button.clicked.connect(self.stop_capture)
        stop_button.setStyleSheet("""
            background-color: #f44336;
            color: white;
            font-size: 14px;
            padding: 10px 20px;
            border-radius: 5px;
            border: none;
        """)
        button_layout.addWidget(stop_button)

        view_details_button = QPushButton("View Packet Details", self)
        view_details_button.clicked.connect(self.view_packet_details)
        view_details_button.setStyleSheet("""
            background-color: #2196f3;
            color: white;
            font-size: 14px;
            padding: 10px 20px;
            border-radius: 5px;
            border: none;
        """)
        button_layout.addWidget(view_details_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def add_packet_to_log(self, src_ip, src_domain, dst_ip, dst_domain, src_port, dst_port, protocol):
        row_position = self.packet_log_table.rowCount()
        self.packet_log_table.insertRow(row_position)
        self.packet_log_table.setItem(row_position, 0, QTableWidgetItem(src_ip))
        self.packet_log_table.setItem(row_position, 1, QTableWidgetItem(src_domain))
        self.packet_log_table.setItem(row_position, 2, QTableWidgetItem(dst_ip))
        self.packet_log_table.setItem(row_position, 3, QTableWidgetItem(dst_domain))
        self.packet_log_table.setItem(row_position, 4, QTableWidgetItem(str(src_port)))
        self.packet_log_table.setItem(row_position, 5, QTableWidgetItem(str(dst_port)))
        self.packet_log_table.setItem(row_position, 6, QTableWidgetItem(protocol))

        self.packet_log_data.append({
            "src_ip": src_ip, "src_domain": src_domain, "dst_ip": dst_ip, "dst_domain": dst_domain,
            "src_port": src_port, "dst_port": dst_port, "protocol": protocol
        })

    def view_packet_details(self):
        current_row = self.packet_log_table.currentRow()
        if current_row >= 0:
            packet_data = self.packet_log_data[current_row]
            details = f"""
                Source IP: {packet_data['src_ip']}
                Source Domain: {packet_data['src_domain']}
                Destination IP: {packet_data['dst_ip']}
                Destination Domain: {packet_data['dst_domain']}
                Source Port: {packet_data['src_port']}
                Destination Port: {packet_data['dst_port']}
                Protocol: {packet_data['protocol']}
            """
            dialog = PacketDetailsDialog(details, self)
            dialog.exec_()

    def resolve_domain(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return "Unknown"

    def start_capture(self):
        if self.capture_running:
            return
        self.capture_running = True
        threading.Thread(target=self.capture_packets, daemon=True).start()
        QMessageBox.information(self, "Capture Started", "Packet capture has started.")

    def stop_capture(self):
        self.capture_running = False
        QMessageBox.information(self, "Capture Stopped", "Packet capture has stopped.")

    def capture_packets(self):
        try:
            def protocol_name(protocol_number):
                if protocol_number == 6:
                    return "TCP"
                elif protocol_number == 17:
                    return "UDP"
                elif protocol_number == 1:
                    return "ICMP"
                elif protocol_number == 2:
                    return "IGMP"
                else:
                    return f"Protocol {protocol_number}"

            def process_packet(packet):
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_domain = self.resolve_domain(src_ip)
                    dst_domain = self.resolve_domain(dst_ip)
                    src_port = packet.sport if hasattr(packet, "sport") else 0
                    dst_port = packet.dport if hasattr(packet, "dport") else 0
                    protocol = protocol_name(packet[IP].proto)

                    self.add_packet_to_log(src_ip, src_domain, dst_ip, dst_domain, src_port, dst_port, str(protocol))

            sniff(prn=process_packet, stop_filter=lambda _: not self.capture_running, store=False)
        except Exception as e:
            print(f"Error: {e}")


class MainApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Main Application")
        self.setGeometry(100, 100, 1200, 800)

        self.tab_widget = QTabWidget()
        self.dns_resolver_tab = DNSResolverApp()
        self.packet_sniffer_tab = PacketSnifferApp()

        self.tab_widget.addTab(self.dns_resolver_tab, "DNS Resolver")
        self.tab_widget.addTab(self.packet_sniffer_tab, "Packet Sniffer")

        layout = QVBoxLayout()
        layout.addWidget(self.tab_widget)

        self.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_app = MainApp()
    main_app.showMaximized()
    sys.exit(app.exec_())
