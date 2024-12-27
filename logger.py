import logging
import json
import csv
from datetime import datetime

logging.basicConfig(filename="dns_queries.log", level=logging.INFO)


def log_query(domain, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"{timestamp} | Query: {domain}, Result: {result}")


def export_log_to_json(log_file="dns_queries.log"):
    queries = []
    with open(log_file, "r") as f:
        for line in f:
            timestamp, query, result = line.split(" | ")
            queries.append(
                {"timestamp": timestamp, "query": query, "result": result.strip()}
            )
    with open("dns_queries.json", "w") as json_file:
        json.dump(queries, json_file, indent=4)


def export_log_to_csv(log_file="dns_queries.log"):
    queries = []
    with open(log_file, "r") as f:
        for line in f:
            timestamp, query, result = line.split(" | ")
            queries.append([timestamp, query, result.strip()])
    with open("dns_queries.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Timestamp", "Query", "Result"])
        writer.writerows(queries)
