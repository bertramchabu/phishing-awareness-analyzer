"""
Phishing Awareness Analyzer — CodeNova Cybersecurity Internship, Task 2.
Analyzes SYNTHETIC email samples only. Performs NO network probes,
NO web requests, NO credential harvesting.
"""

import argparse
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "verify your account",
    "act now",
    "suspended",
    "final warning",
    "within 24 hours",
    "click below",
    "confirm your identity",
    "unusual activity",
    "your account will be locked",
]
CREDENTIAL_CUES = [
    "password",
    "login",
    "sign in",
    "username",
    "credentials",
    "pin",
    "ssn",
]

URL_RE = re.compile(r"""https?://[^\s<>"')]+""", re.IGNORECASE)
BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "bank"]


def analyze_url(url: str) -> dict:
    findings = []
    score = 0
    host = (urlsplit(url).hostname or "").lower()

    is_ipv4 = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) is not None
    if is_ipv4:
        findings.append("URL uses a raw IP address instead of a domain.")
        score += 25
    if not is_ipv4 and host.count(".") >= 3:
        findings.append(
            "Deeply nested subdomains may be misleading (subdomain spoofing)."
        )
        score += 15
    for brand in BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            findings.append(
                f"Brand name '{brand}' appears in a non-official domain "
                "(possible typosquatting)."
            )
            score += 25
    if re.search(r"(login|secure|verify|update)[.-]", host):
        findings.append("Host contains lure words like 'login'/'verify'/'secure'.")
        score += 10

    return {"url": url, "findings": findings, "score": min(score, 40)}


def analyze_email(raw_bytes: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    findings = []
    header_score = 0

    from_hdr = str(msg.get("From", ""))
    from_domain = (
        from_hdr.split("@")[-1].strip(" >").lower() if "@" in from_hdr else ""
    )
    reply_to = str(msg.get("Reply-To", ""))
    if reply_to and from_domain and from_domain not in reply_to.lower():
        findings.append("Reply-To domain differs from From domain.")
        header_score += 15
    auth = (
        str(msg.get("Authentication-Results", ""))
        + " "
        + str(msg.get("Received-SPF", ""))
    ).lower()
    if "spf=fail" in auth or "dkim=fail" in auth:
        findings.append("SPF/DKIM failure flag present in headers.")
        header_score += 25

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_content()
                if isinstance(content, str):
                    body += content
    else:
        content = msg.get_content()
        if isinstance(content, str):
            body = content

    body_lower = body.lower()
    urgency_hits = [word for word in URGENCY_WORDS if word in body_lower]
    body_score = 0
    if urgency_hits:
        findings.append(
            f"High-urgency language detected: {', '.join(urgency_hits[:4])}."
        )
        body_score += min(10 + 5 * len(urgency_hits), 25)
    credential_hits = [word for word in CREDENTIAL_CUES if word in body_lower]
    if credential_hits:
        findings.append(
            f"Credential-related terms detected: {', '.join(credential_hits[:4])}."
        )
        body_score += 15

    url_score = 0
    for url in URL_RE.findall(body):
        result = analyze_url(url)
        if result["score"]:
            findings.extend(result["findings"])
            url_score = min(url_score + result["score"], 40)

    score = min(header_score + body_score + url_score, 100)
    if score >= 60:
        level = "High risk"
    elif score >= 30:
        level = "Suspicious"
    else:
        level = "Low risk"
    return {"from": from_hdr, "score": score, "level": level, "findings": findings}


def report(result: dict) -> str:
    lines = [
        "DISCLAIMER: This educational heuristic can produce false positives.",
        "Use synthetic samples only; a score is not proof that an email is malicious.",
        "",
        f"Sender: {result['from']}",
        f"Risk score: {result['score']}/100 - {result['level']}",
        "",
        "Explanation breakdown:",
    ]
    lines += [f"  - {finding}" for finding in result["findings"]] or [
        "  - No strong indicators found."
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a synthetic email sample for phishing indicators."
    )
    parser.add_argument("email_file", help="Path to a synthetic .eml file")
    args = parser.parse_args()

    with open(args.email_file, "rb") as email_file:
        print(report(analyze_email(email_file.read())))


if __name__ == "__main__":
    main()
