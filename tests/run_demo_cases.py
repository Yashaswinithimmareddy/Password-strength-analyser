"""
Safe Synthetic Demonstration Runner
-----------------------------------
Runs the 5 standardized benchmark demonstration cases specified in Section 29.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import generate_secure_password

cases = [
    ("TEST 1", "123456", "Common, short, sequential numeric"),
    ("TEST 2", "Password123!", "Classic corporate formula: Word + digits + symbol"),
    ("TEST 3", "aaaaaaaaaaaaaaaa", "Long (16 chars) but single repetitive character"),
    ("TEST 4", "qwerty2026!", "Keyboard walk + predictable year"),
    ("TEST 5", generate_secure_password(length=20)["password"], "CSPRNG 20-char cryptographically random")
]

print("=" * 70)
print("DEFENSIVE PASSWORD STRENGTH ANALYZER - DEMO TEST EXECUTION")
print("=" * 70)

for test_id, pwd, scenario in cases:
    res = analyze_password(pwd, persist_analytics=False)
    score = res["score"]
    classification = res["classification"]
    length = res["metrics"]["length"]["length"]
    band = res["metrics"]["length"]["band"]
    adj_ent = res["metrics"]["entropy"]["adjusted_bits"]
    findings_count = len(res["findings"])

    print(f"\n{test_id}: Scenario -> {scenario}")
    print(f"  Input:          {pwd}")
    print(f"  Length:         {length} chars ({band})")
    print(f"  Adjusted Entr:  {adj_ent} bits")
    print(f"  Score:          {score} / 100")
    print(f"  Classification: {classification}")
    print(f"  Weaknesses:     {findings_count} detected")
    for f in res["findings"]:
        print(f"    - [{f['category']}] {f['description']}")
    if res["suggestions"]:
        print(f"  Recommendation: {res['suggestions'][0]['title']}")
    print("-" * 70)
