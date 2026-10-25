# Phishing Message Checker

**IncodeVision Cyber Security Internship — Task 04**

A local Python CLI tool that checks pasted email/message text for common phishing indicators. It does not fetch or open links.

## Features
- Finds URLs in pasted messages
- Flags urgency, credential/OTP requests, and financial-lure wording
- Notes URL shorteners and IP-address URLs
- Displays a simple indicator score and verdict
- Gives practical safety advice
- Does not save analyzed messages to disk

## Run
```bash
python3 main.py
```
Paste harmless sample text and type `END` on a separate line. Example:
```text
URGENT ACTION: Verify your account immediately within 24 hours.
Confirm your password using https://example.com/login
END
```

## Limitations
Heuristic demo only. Legitimate messages may trigger warnings and malicious messages may evade these patterns. A low score does not prove a message is safe. Verify requests through an independent official channel.
