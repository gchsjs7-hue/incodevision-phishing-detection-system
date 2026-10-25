import re
from dataclasses import dataclass

URL_RE = re.compile(r"https?://[^\s<>\[\]()\"']+|www\.[^\s<>\[\]()\"']+", re.IGNORECASE)
PHRASES = {
    "Urgency": ["urgent action", "act now", "immediately", "account will be suspended", "verify immediately", "within 24 hours", "unusual activity"],
    "Credential or OTP request": ["confirm your password", "enter your password", "verify your account", "provide your credentials", "share your otp", "send your otp", "one-time password"],
    "Financial lure": ["you have won", "claim your prize", "free gift", "refund pending", "payment failed", "gift card"]
}

@dataclass
class Finding:
    category: str
    detail: str
    points: int

def analyze(message):
    findings, lowered = [], message.lower()
    urls = URL_RE.findall(message)
    if urls:
        findings.append(Finding("Links", f"Found {len(urls)} URL(s); inspect destinations carefully.", 1))
    for category, phrases in PHRASES.items():
        matches = [phrase for phrase in phrases if phrase in lowered]
        if matches:
            findings.append(Finding(category, "Potentially suspicious wording: " + ", ".join(matches[:4]), min(3, len(matches))))
    shorteners = ("bit.ly/", "tinyurl.com/", "t.co/", "is.gd/", "cutt.ly/", "rb.gy/")
    if any(shortener in url.lower() for url in urls for shortener in shorteners):
        findings.append(Finding("Obfuscated destination", "URL shortener detected; preview destination safely.", 2))
    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", message, re.IGNORECASE):
        findings.append(Finding("IP-based link", "URL uses an IP address instead of a domain.", 2))
    score = min(10, sum(item.points for item in findings))
    if score >= 6: verdict = "HIGH RISK INDICATORS"
    elif score >= 3: verdict = "SUSPICIOUS — REVIEW CAREFULLY"
    elif score >= 1: verdict = "CAUTION — CHECK LINKS"
    else: verdict = "NO OBVIOUS INDICATORS FOUND"
    return verdict, score, findings, urls

def main():
    print("PHISHING MESSAGE CHECKER - TASK 04")
    print("Paste a message or email body. Type END on its own line when finished.\n")
    lines = []
    while True:
        try: line = input()
        except EOFError: break
        if line.strip().upper() == "END": break
        lines.append(line)
    message = "\n".join(lines).strip()
    if not message:
        print("No message entered."); return
    verdict, score, findings, urls = analyze(message)
    print(f"\nVerdict: {verdict}\nIndicator score: {score}/10")
    if urls:
        print("\nURLs found (do not open suspicious links):")
        for url in urls: print(f"- {url}")
    if findings:
        print("\nFindings:")
        for finding in findings: print(f"- [{finding.category}] {finding.detail}")
    else:
        print("No configured warning patterns detected.")
    print("\nSafety advice: never enter passwords or OTPs through message links; verify requests independently.")
    print("Note: heuristic demo only; a low score does not prove a message is safe.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nAnalysis cancelled.")
