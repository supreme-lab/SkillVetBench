#!/usr/bin/env python3
"""
diagnostic.py — run this to identify why server.py won't load
Usage: python diagnostic.py
"""
import sys, os, socket
from pathlib import Path

print("=" * 60)
print("  AgentSkillBench — Startup Diagnostic")
print("=" * 60)

# 1. Check port 8000
def check_port(port=8000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex(("127.0.0.1", port))
        return result == 0

port_in_use = check_port(8000)
print(f"\n1. Port 8000 already in use: {'❌ YES — kill the old process first' if port_in_use else '✅ Free'}")
if port_in_use:
    print("   Run:  kill $(lsof -t -i:8000)  or  pkill -f \'python server.py\'")

# 2. Check required files
print("\n2. Required files:")
required = [
    "server.py", "storage.py", "evaluator.py", "llm_client.py",
    "sars.py", "prompts_cvss4_0.py", "prompts_clawhub.py",
    "cvss4_0.py", "templates.html", "metrics.json",
]
for f in required:
    exists = Path(f).exists()
    print(f"   {'✅' if exists else '❌ MISSING'} {f}")

# 3. Check Python imports
print("\n3. Python imports:")
imports = [
    ("fastapi", "pip install fastapi"),
    ("uvicorn", "pip install uvicorn[standard]"),
    ("httpx",   "pip install httpx"),
    ("anthropic","pip install anthropic"),
]
for mod, install in imports:
    try:
        __import__(mod)
        print(f"   ✅ {mod}")
    except ImportError:
        print(f"   ❌ {mod} missing — run: {install}")

# 4. Test templates.html loading
print("\n4. templates.html loading:")
try:
    SEP = "<!-- ==================== DETAIL_PAGE ==================== -->"
    content = Path("templates.html").read_text(encoding="utf-8")
    parts = content.split(SEP, 1)
    if len(parts) == 2:
        print(f"   ✅ Loaded OK ({len(content):,} chars)")
    else:
        print("   ❌ Separator missing in templates.html")
except Exception as e:
    print(f"   ❌ {e}")

# 5. Test storage
print("\n5. Storage:")
try:
    sys.path.insert(0, ".")
    from storage import ReportStorage
    st = ReportStorage("reports")
    lb = st.get_leaderboard()
    print(f"   ✅ Storage OK ({len(lb)} reports in index)")
except Exception as e:
    print(f"   ❌ {e}")

# 6. Test server.py import
print("\n6. server.py import test:")
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("server", "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    print("   ✅ server.py imports and initialises OK")
except Exception as e:
    print(f"   ❌ server.py failed: {e}")

print("\n" + "=" * 60)
print("  Share any ❌ lines with the assistant for targeted fixes.")
print("=" * 60)