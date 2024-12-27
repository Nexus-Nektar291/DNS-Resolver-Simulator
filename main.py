import sys
from dns_resolver import resolve
import argparse


def main():
    parser = argparse.ArgumentParser(description="DNS Resolver - Command Line Mode")
    parser.add_argument("domain", help="Domain to resolve")
    parser.add_argument(
        "query_type",
        choices=["A", "AAAA", "MX", "CNAME", "PTR"],
        help="Type of DNS query",
    )
    parser.add_argument(
        "method", choices=["recursive", "iterative"], help="DNS resolution method"
    )
    args = parser.parse_args()

    results = resolve(args.domain, args.query_type, args.method)
    print("\n".join(results) if results else "No results.")


if __name__ == "__main__":
    main()


