import json
import os


class Cache:
    def __init__(self, cache_file="dns_cache.json"):
        self.cache_file = cache_file
        self.load_cache()

    def load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r") as f:
                self.cache = json.load(f)
        else:
            self.cache = {}

    def get(self, domain, record_type):
        return self.cache.get(domain, {}).get(record_type)

    def set(self, domain, record_type, result):
        if domain not in self.cache:
            self.cache[domain] = {}
        self.cache[domain][record_type] = result
        self.save_cache()

    def save_cache(self):
        with open(self.cache_file, "w") as f:
            json.dump(self.cache, f)
