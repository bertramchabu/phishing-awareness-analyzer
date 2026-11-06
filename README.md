# Phishing Awareness Analyzer

An educational, heuristic analyzer for **synthetic email samples only**. It
parses `.eml` files with Python's standard-library `email` package and checks
message headers, body text, and embedded URLs. It does not determine whether an
email is definitively malicious.

> **False-positive disclaimer:** This tool can flag legitimate messages and
> miss malicious ones. Its score is an educational signal, not proof. Verify
> suspicious messages through trusted channels and never provide credentials
> in response to an email.

## Safety and scope

- **No network calls:** the analyzer makes no network requests or probes. URL
  checks are performed only against the URL text found in the message.
- It does not harvest, transmit, or request credentials.
- All included `.eml` samples are synthetic and intended for awareness training.

## Heuristics and scoring

The total score is capped at 100 points. Indicators are additive, with these
category limits:

| Category | Indicator | Points |
| --- | --- | ---: |
| Headers (max 40) | Reply-To domain differs from the From domain | 15 |
| Headers (max 40) | SPF or DKIM failure flag in authentication headers | 25 |
| Body (max 40) | Urgency language: 10 points plus 5 per matched phrase, capped at 25 | 10–25 |
| Body (max 40) | Credential-related terms detected | 15 |
| URLs (max 40) | Raw IPv4 address in URL host | 25 |
| URLs (max 40) | At least four host labels (deeply nested subdomains) | 15 |
| URLs (max 40) | A known brand name in a domain not ending in that brand's `.com` domain | 25 per match |
| URLs (max 40) | Lure words such as `login`, `secure`, `verify`, or `update` in the host | 10 |

URL indicator points are capped at 40 for the whole email; the overall score is
also capped at 100. Multiple email-body indicators can contribute, subject to
their category limits.

Risk levels:

- **High risk:** score ≥ 60
- **Suspicious:** score ≥ 30 and < 60
- **Low risk:** score < 30

These are heuristic thresholds, not a verdict.

## Run

Requires Python 3 and no third-party packages:

```text
python phishing_analyzer.py samples/phishing_01.eml
python phishing_analyzer.py samples/legit_01.eml
```

The phishing sample should be reported as High risk and include indicators for
SPF/DKIM failure, a raw-IP URL, urgency language, and a Reply-To mismatch.

## Web interface

Start the local interface with:

```text
python ui_server.py
```

Then open `http://127.0.0.1:8000` in a browser. Upload an `.eml` file up to
1 MB or try one of the included synthetic samples. The interface binds only to
localhost; submitted email bytes are analyzed in memory and are not saved.
Analysis makes no external network requests. Press Ctrl+C in the terminal to
stop the server.