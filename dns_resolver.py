import socket
import dns.resolver


def resolve(domain, query_type, method):
    # If the query type is PTR, handle reverse DNS lookup
    if query_type == "PTR":
        return resolve_reverse_dns(domain)

    # Otherwise, resolve using standard DNS methods
    if method == "recursive":
        return resolve_recursive(domain, query_type)
    elif method == "iterative":
        return resolve_iterative(domain, query_type)


def resolve_recursive(domain, query_type):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, query_type)
        return [answer.to_text() for answer in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return ["Domain does not exist."]
    except Exception as e:
        return [f"Error: {str(e)}"]


def resolve_iterative(domain, query_type):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, query_type)
        return [answer.to_text() for answer in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return ["Domain does not exist."]
    except Exception as e:
        return [f"Error: {str(e)}"]


def resolve_reverse_dns(ip_address):
    try:
        host = socket.gethostbyaddr(ip_address)[0]
        return [host]
    except socket.herror:
        return ["No PTR record found"]
