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
    QTreeWidget,
    QTreeWidgetItem,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from dns_resolver import resolve  # Assuming resolve is implemented in dns_resolver.py
from cache import Cache  # Assuming cache.py is implemented


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
        self.cache = Cache()  # Initialize cache
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
            self.cache.set(domain, query_type, results)  # Store in cache

            # Update query history table
            self.update_query_history_table(domain, query_type, results)

            self.results_display.append(
                f"Successfully resolved {domain} to {', '.join(results)}"
            )
        except Exception as e:
            self.results_display.append(f"Error: {str(e)}")

    def resolve_reverse_dns(self, ip_address):
        try:
            import socket

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
        self.query_history_table.setItem(
            row_position, 2, result_item
        )  # Use QTableWidgetItem object

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

            # Show success message
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

            # Show success message
            QMessageBox.information(
                self,
                "Export Successful",
                "Query history exported to dns_query_history.json",
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting to JSON: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    dns_resolver_app = DNSResolverApp()
    dns_resolver_app.show()
    sys.exit(app.exec_())
