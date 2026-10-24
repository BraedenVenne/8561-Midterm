import requests
import csv
import time
from textwrap import dedent

# Runs HTTP scan against local server and audits security headers
def run_http_checker():
    BASE_URL = "http://127.0.0.1:8765"
    observations = []
    findings = []
    seen_findings = set()

    print(f"\nStarting HTTP Scan on ({BASE_URL})...")

    # Test base connection
    try:
        response = requests.get(BASE_URL, timeout=5)
        print(f"Connected. Status: {response.status_code}")
        print(f"Response length: {len(response.content)} bytes")
    except requests.RequestException as error:
        print(f"Could not connect: {error}")
        return

    # Store HTTP observations into global list
    def store_observation(r, endpoint):
        observations.append({
            "Endpoint": endpoint,
            "HTTP Method": "GET",
            "Status": r.status_code,
            "Response Length": len(r.content),
            "Content Type": r.headers.get("Content-Type", ""),
            "Server Header": r.headers.get("Server", "")
        })

    # Store findings with conditional uniqueness (Global for Info Disclosure, Per-Endpoint for others)
    def store_finding(category, endpoint, observation, review_status):
        if category == "Information Disclosure":
            finding_key = (category, observation)
        else:
            finding_key = (category, endpoint, observation)

        if finding_key not in seen_findings:
            seen_findings.add(finding_key)
            findings.append({
                "Category": category,
                "Endpoint": endpoint,
                "Observation": observation,
                "Review Status": review_status
            })

    # Format observation for console output
    def format_observation(observation_num, r, endpoint):
        observation_output = dedent(
            f"""
            Observation {observation_num}:
            Endpoint: {endpoint}
            HTTP Method: GET
            Status: {r.status_code}
            Response Length: {len(r.content)}
            Content Type: {r.headers.get('Content-Type', '')}
            Server Header: {r.headers.get('Server', '')}
            """
        )
        return observation_output

    test_urls = ["/", "/health", "/redirect", "/missing"]
    observation_num = 1

    print("\nHTTP Observations:")
    # Iterate through target endpoints
    for endpoint in test_urls:
        url = BASE_URL + endpoint
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            store_observation(r, endpoint)
            print(format_observation(observation_num, r, endpoint))
            observation_num += 1
            time.sleep(0.3)

            # Check for missing security response headers
            security_headers = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
            missing_headers = [h for h in security_headers if h not in r.headers]
            if missing_headers:
                store_finding(
                    "Security Misconfiguration",
                    endpoint,
                    f"Response is missing the following headers: {missing_headers}",
                    "Investigate missing header relevance"
                )

            # Check server header information disclosure (logged once globally)
            server_header = r.headers.get("Server")
            if server_header:
                store_finding(
                    "Information Disclosure",
                    endpoint,
                    f"Server header revealed: {server_header}",
                    "Informational - Identifies implementation stack"
                )

            # Check cookie attributes on root endpoint
            if endpoint == "/" and "Set-Cookie" in r.headers:
                store_finding(
                    "Cookie Security",
                    endpoint,
                    f"Set-Cookie header present: {r.headers.get('Set-Cookie')}",
                    "Review Cookie Flags (Missing HttpOnly/Secure attributes)"
                )

        except requests.RequestException as error:
            print(f"Could not connect to {endpoint}: {error}")

    # Export observations to a CSV file matching your required columns
    csv_filename = "http_scan_results.csv"
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=[
            "Endpoint",
            "HTTP Method",
            "Status",
            "Response Length",
            "Content Type",
            "Server Header"
        ])
        writer.writeheader()
        writer.writerows(observations)

    print(f"Saved {csv_filename}")

    # Format findings for console output
    def format_finding(finding_num, f):
        finding_output = dedent(
            f"""
            Finding {finding_num}:
            Category: {f['Category']}
            Endpoint: {f['Endpoint']}
            Observation: {f['Observation']}
            Review Status: {f['Review Status']}
            """
        )
        return finding_output

    print(f"\nStarting Vulnerability SCAN on {BASE_URL}...")
    finding_num = 1
    for f in findings:
        print(format_finding(finding_num, f))
        finding_num += 1
        time.sleep(0.4)

    if not findings:
        print("No indicators found.")

    # Export findings to CSV
    findings_csv = "vulnerability_findings.csv"
    with open(findings_csv, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=[
            "Category",
            "Endpoint",
            "Observation",
            "Review Status"
        ])
        writer.writeheader()
        writer.writerows(findings)

    print(f"Saved {findings_csv}\n")