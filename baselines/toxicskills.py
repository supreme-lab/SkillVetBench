import os
import re

def scan_for_toxicskills(directory):
    suspicious_patterns = {
        "HTML Comment Injection": r'<!--[\s\S]*?(SYSTEM|OVERRIDE|EXECUTE|curl|wget|bash|sh)[\s\S]*?-->',
        "Base64 Obfuscation": r'(base64\s+-d|base64\s+--decode)',
        "Pipe to Shell": r'\|\s*(bash|sh|python)',
        "Bare IP Address (C2)": r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        "Suspicious Curl/Wget": r'(curl|wget).*?(-s|-q|--silent)'
    }

    print(f"🛡️ Scanning {directory} for ToxicSkill vectors...\n")
    findings = 0

    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(('.md', '.txt', '.json')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_findings = []
                    for name, pattern in suspicious_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                            file_findings.append(name)

                    if file_findings:
                        findings += 1
                        print(f"⚠️  [ALERT] {filepath}")
                        for flaw in file_findings:
                            print(f"    └── Detected: {flaw}")

                except Exception as e:
                    print(f"Error reading {filepath}: {e}")

    if findings == 0:
        print("\n✅ No obvious ToxicSkill patterns detected.")
    else:
        print(f"\n🚨 Scan complete. {findings} suspicious files found.")

# Usage
scan_for_toxicskills("./my_agent_skills")