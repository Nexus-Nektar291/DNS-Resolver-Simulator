import requests
import time
from collections import defaultdict
import matplotlib.pyplot as plt


class AdvancedDNSAddons:
    def __init__(self):
        self.query_logs = []  # To store query logs
        self.rate_limit = defaultdict(int)  # Track queries per IP
        self.rate_limit_window = 60  # Rate limit window in seconds
        self.max_queries_per_window = 10  # Max allowed queries per IP

    def dns_over_https(self, domain, query_type="A"):
        """Perform a DNS query over HTTPS (DoH)."""
        url = "https://dns.google/resolve"
        params = {"name": domain, "type": query_type}
        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
            return data.get("Answer", [])
        except requests.RequestException as e:
            print(f"Error performing DoH query: {e}")
            return []

    def is_rate_limited(self, source_ip):
        """Check if the source IP is exceeding the allowed rate limit."""
        now = time.time()

        if source_ip not in self.rate_limit:
            self.rate_limit[source_ip] = [now]
            return False

        # Filter out old timestamps
        self.rate_limit[source_ip] = [
            ts for ts in self.rate_limit[source_ip] if now - ts < self.time_window
        ]

        # Add the current timestamp
        self.rate_limit[source_ip].append(now)

        # Check if the rate limit is exceeded
        if len(self.rate_limit[source_ip]) > self.max_requests:
            return True

        return False

    def log_query(self, domain, query_type, source_ip):
        """Log a DNS query."""
        self.query_logs.append(
            {
                "timestamp": time.time(),
                "domain": domain,
                "query_type": query_type,
                "source_ip": source_ip,
            }
        )

    def visualize_logs(self):
        """Visualize DNS query logs."""
        if not self.query_logs:
            print("No logs to visualize.")
            return

        timestamps = [log["timestamp"] for log in self.query_logs]
        domains = [log["domain"] for log in self.query_logs]
        plt.figure(figsize=(10, 6))
        plt.scatter(timestamps, domains, alpha=0.6)
        plt.title("DNS Query Logs")
        plt.xlabel("Timestamp")
        plt.ylabel("Domain")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()
