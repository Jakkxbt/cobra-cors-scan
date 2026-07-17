#!/usr/bin/env python3
"""
cors-scan — CORS Misconfiguration Scanner
Authorised red-team tool. Test only against targets you own or are contracted to test.

Finds exploitable CORS misconfigurations by testing forged Origin headers and analyzing
Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials (ACAC) responses.
"""
import sys
import argparse
import urllib.request
import urllib.parse
import json
from urllib.error import URLError, HTTPError

USER_AGENT = "cors-scan/1.0 (authorised security testing)"
TIMEOUT = 8

def build_test_origins(url: str) -> list:
    """Attacker-controlled test origins derived from the TARGET host, so the
    prefix/suffix/substring bypass probes are meaningful for whatever we scan
    (not hardcoded to one domain)."""
    host = urllib.parse.urlparse(url).hostname or ""
    origins = [
        ("arbitrary", "https://evil.example"),
        ("null", "null"),
    ]
    if host:
        origins += [
            ("prefix_bypass", f"https://{host}.evil.example"),        # target is a prefix
            ("suffix_bypass", f"https://evil{host}"),                 # target is a suffix (evil+host)
            ("substring_bypass", f"https://sub.{host}.evil.example"), # target appears mid-origin
        ]
    return origins


def fetch_response(url: str, origin: str = None, timeout: int = TIMEOUT) -> dict:
    """Send HTTP request and return response details."""
    headers = {
        "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

    if origin is not None:
        headers["Origin"] = origin

    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode('utf-8', errors='ignore')
            headers_dict = dict(response.headers)

            return {
                "success": True,
                "status": response.status,
                "headers": headers_dict,
                "body": body,
                "error": None
            }
    except HTTPError as e:
        return {
            "success": True,
            "status": e.code,
            "headers": dict(e.headers),
            "body": e.read().decode('utf-8', errors='ignore'),
            "error": None
        }
    except URLError as e:
        return {
            "success": False,
            "status": None,
            "headers": {},
            "body": "",
            "error": f"{e.__class__.__name__}: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "status": None,
            "headers": {},
            "body": "",
            "error": f"{e.__class__.__name__}: {e}"
        }


def get_header(headers: dict, name: str, default: str = "") -> str:
    """Get a header value, case-insensitive."""
    if not headers:
        return default
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value if value else default
    return default


def test_origin_reflection(url: str, origin: str, origin_type: str) -> dict:
    """Test if a forged origin is reflected in ACAO."""
    response = fetch_response(url, origin)

    if not response["success"]:
        return {
            "origin_type": origin_type,
            "origin": origin,
            "status_code": None,
            "acao": None,
            "acac": None,
            "error": response["error"],
            "evidence": {
                "origin": origin,
                "target": url
            }
        }

    acao = get_header(response["headers"], "Access-Control-Allow-Origin", "")
    acac = get_header(response["headers"], "Access-Control-Allow-Credentials", "")

    is_acac_true = acac.lower() == "true"

    return {
        "origin_type": origin_type,
        "origin": origin,
        "status_code": response["status"],
        "acao": acao,
        "acac": is_acac_true,
        "error": None,
        "evidence": {
            "origin": origin,
            "target": url,
            "acao": acao,
            "acac": acac
        }
    }


def analyze_reflection(result: dict) -> dict:
    """Analyze a single origin reflection test."""
    origin = result["origin"]
    acao = result["acao"]
    acac = result["acac"]
    origin_type = result["origin_type"]
    error = result["error"]

    if error:
        return {
            "severity": None,
            "title": f"CORS check failed: {origin_type}",
            "description": error,
            "evidence": result["evidence"]
        }

    # If no ACAO header at all, no reflection
    if not acao:
        return {
            "severity": None,
            "title": f"No ACAO returned for {origin_type}",
            "description": "Server returned no ACAO header",
            "evidence": result["evidence"]
        }

    # A finding exists only when the server reflects our ATTACKER-CONTROLLED origin
    # (arbitrary / null / prefix / suffix / substring bypass) back in ACAO. If it
    # returns its own fixed origin, or nothing, that is safe — report nothing.
    acao_reflected = acao == origin
    is_wildcard = acao == "*"

    severity = None
    title = ""
    description = ""

    if acao_reflected and acac:
        severity = "HIGH"
        label = {"arbitrary": "arbitrary origin", "null": "null origin"}.get(
            origin_type, f"attacker origin via {origin_type}")
        title = f"Reflected {label} with credentials enabled"
        description = (
            f"ACAO echoes attacker-controlled origin '{origin}' and ACAC is true. "
            "Allows credentialled cross-origin data theft (cookie/session theft, CSRF bypass)."
        )
    elif acao_reflected and not acac:
        severity = "LOW"
        title = f"Reflected attacker origin without credentials ({origin_type})"
        description = (
            f"ACAO echoes attacker-controlled origin '{origin}' but ACAC is not true. "
            "Cross-origin reads of unauthenticated responses are possible; credential theft is blocked."
        )
    elif is_wildcard:
        severity = "INFO"
        title = "Wildcard ACAO (*) — permissive but not credential-exploitable"
        description = (
            "ACAO is '*', which browsers block for credentialled requests. "
            "Not directly exploitable, but indicates a permissive CORS policy."
        )
    # else: server returned its own or a non-attacker origin -> clean, no finding.

    return {
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": result["evidence"]
    }


def scan_target(url: str, output_format: str = "text") -> dict:
    """Scan a target for CORS misconfigurations."""
    test_origins = build_test_origins(url)
    print(f"[*] Scanning target: {url}")
    print(f"[*] Testing {len(test_origins)} origin types...")

    findings = []

    for origin_type, origin in test_origins:
        print(f"[*] Testing: {origin_type} ({origin})")
        result = test_origin_reflection(url, origin, origin_type)
        analysis = analyze_reflection(result)

        if analysis["severity"]:
            findings.append(analysis)

    # Sort by severity (HIGH > LOW > INFO)
    severity_order = {"HIGH": 0, "LOW": 1, "INFO": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 999))

    return {
        "target": url,
        "findings": findings,
        "total_findings": len(findings),
        "high_findings": len([f for f in findings if f["severity"] == "HIGH"]),
        "low_findings": len([f for f in findings if f["severity"] == "LOW"]),
        "info_findings": len([f for f in findings if f["severity"] == "INFO"])
    }


def print_text_results(result: dict):
    """Print results in text format."""
    print(f"\n{'='*60}")
    print("CORS SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Target: {result['target']}")
    print(f"Total findings: {result['total_findings']}")
    print(f"  HIGH: {result['high_findings']}")
    print(f"  LOW:  {result['low_findings']}")
    print(f"  INFO: {result['info_findings']}")
    print(f"{'='*60}\n")

    if not result["findings"]:
        print("No exploitable CORS misconfigurations found.")
        return

    for i, finding in enumerate(result["findings"], 1):
        print(f"{i}. [{finding['severity']}] {finding['title']}")
        print(f"   {finding['description']}")
        print(f"   Evidence:")
        print(f"     Origin: {finding['evidence']['origin']}")
        print(f"     ACAO: {finding['evidence']['acao']}")
        print(f"     ACAC: {finding['evidence']['acac']}")
        print()


def print_json_results(result: dict):
    """Print results in JSON format."""
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="cors-scan — CORS Misconfiguration Scanner",
        epilog="Authorised use only. Test only against targets you own."
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout in seconds")
    args = parser.parse_args()

    result = scan_target(args.url, "json" if args.json else "text")

    if args.json:
        print_json_results(result)
    else:
        print_text_results(result)

    # Exit code based on highest severity
    if result["high_findings"] > 0:
        sys.exit(2)  # Vulnerable
    elif result["low_findings"] > 0:
        sys.exit(1)  # Needs review
    elif result["info_findings"] > 0:
        sys.exit(0)  # Informational only
    else:
        sys.exit(0)  # Clean


if __name__ == "__main__":
    main()
