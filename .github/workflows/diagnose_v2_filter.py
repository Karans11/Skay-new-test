#!/usr/bin/env python3
"""
Diagnostic for proposed filter: failed + hasExploit + fixedVersion.

Reads image-layers.json, applies the new filter, predicts the final
count. Read-only. Does not modify any files.

Output answers:
  - Of the 169 "Failed" findings, how many have hasExploit=True?
  - How many have fixedVersion?
  - How many have BOTH (this is the new filter result)?
  - What does the breakdown look like by severity?
"""
import json
import os
import sys
from collections import Counter, defaultdict


def main():
    json_path = "image-layers.json"
    if not os.path.exists(json_path):
        print(f"❌ {json_path} not found")
        sys.exit(1)

    with open(json_path) as f:
        data = json.load(f)

    print("=" * 80)
    print("PROPOSED FILTER DIAGNOSTIC")
    print("=" * 80)
    print()
    print("Filter rules:")
    print("  1. failedPolicyMatches is non-empty (Wiz policy Failed)")
    print("  2. hasExploit == True")
    print("  3. fixedVersion != null")
    print()

    # ============================================================
    # Walk all findings, apply each filter step, count
    # ============================================================
    total = 0
    failed = 0
    failed_with_exploit = 0
    failed_with_fix = 0
    failed_with_both = 0
    failed_with_neither = 0

    # Detailed breakdowns
    severity_counts = Counter()        # for failed-with-both
    sample_kept = []                    # samples that pass all filters
    sample_dropped_no_exploit = []      # failed + has fix, but no exploit
    sample_dropped_no_fix = []          # failed + has exploit, but no fix
    sample_dropped_neither = []         # failed but no exploit + no fix

    result = data.get("result") or {}
    for source_key in ["osPackages", "libraries", "applications"]:
        for pkg in result.get(source_key, []) or []:
            for vuln in pkg.get("vulnerabilities", []) or []:
                cve = (vuln.get("name") or "").strip()
                if not cve:
                    continue
                total += 1

                # First filter: must be in failedPolicyMatches
                if not vuln.get("failedPolicyMatches"):
                    continue

                failed += 1

                has_exploit = bool(vuln.get("hasExploit"))
                has_fix = vuln.get("fixedVersion") is not None and \
                          str(vuln.get("fixedVersion")).strip() != ""

                if has_exploit:
                    failed_with_exploit += 1
                if has_fix:
                    failed_with_fix += 1

                if has_exploit and has_fix:
                    failed_with_both += 1
                    sev = (vuln.get("severity") or "UNKNOWN").upper()
                    severity_counts[sev] += 1
                    if len(sample_kept) < 5:
                        sample_kept.append({
                            "cve": cve,
                            "component": pkg.get("name"),
                            "version": pkg.get("version"),
                            "fixed": vuln.get("fixedVersion"),
                            "severity": sev,
                            "hasKev": vuln.get("hasCisaKevExploit", False),
                        })
                elif not has_exploit and not has_fix:
                    failed_with_neither += 1
                    if len(sample_dropped_neither) < 3:
                        sample_dropped_neither.append({
                            "cve": cve,
                            "component": pkg.get("name"),
                            "version": pkg.get("version"),
                            "severity": (vuln.get("severity") or "").upper(),
                        })
                elif not has_exploit:
                    if len(sample_dropped_no_exploit) < 3:
                        sample_dropped_no_exploit.append({
                            "cve": cve,
                            "component": pkg.get("name"),
                            "fixed": vuln.get("fixedVersion"),
                            "severity": (vuln.get("severity") or "").upper(),
                        })
                else:  # not has_fix
                    if len(sample_dropped_no_fix) < 3:
                        sample_dropped_no_fix.append({
                            "cve": cve,
                            "component": pkg.get("name"),
                            "version": pkg.get("version"),
                            "severity": (vuln.get("severity") or "").upper(),
                        })

    # ============================================================
    # Report
    # ============================================================
    print(f"📊 FINDING UNIVERSE")
    print(f"   Total in JSON:           {total:>5}")
    print(f"   Failed (Wiz policy):     {failed:>5}")
    print()

    print(f"📊 OF {failed} FAILED FINDINGS, BREAKDOWN BY EXPLOIT/FIX")
    print(f"   With exploit:            {failed_with_exploit:>5}")
    print(f"   With fix:                {failed_with_fix:>5}")
    print(f"   With BOTH (KEEP):        {failed_with_both:>5}  ← new GitHub count")
    print(f"   With NEITHER (drop):     {failed_with_neither:>5}")
    failed_no_exploit = failed - failed_with_exploit
    failed_no_fix = failed - failed_with_fix
    print(f"   No exploit (drop):       {failed_no_exploit:>5}")
    print(f"   No fix (drop):           {failed_no_fix:>5}")
    print()

    if total:
        kept_pct = (failed_with_both / total * 100)
        print(f"📊 NOISE REDUCTION")
        print(f"   {total} raw → {failed_with_both} actionable ({kept_pct:.1f}% kept)")
        print(f"   {(1 - kept_pct / 100) * 100:.1f}% reduction")
        print()

    if severity_counts:
        print(f"📊 KEPT FINDINGS BY SEVERITY")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
            if sev in severity_counts:
                print(f"   {sev:<15}        {severity_counts[sev]:>5}")
        print()

    print(f"📋 SAMPLE: KEPT (Failed + Exploit + Fix)")
    for s in sample_kept:
        kev = " 🚨 KEV" if s["hasKev"] else ""
        print(f"   {s['cve']:<18} {s['component']:<25} {s['version'][:20]:<20} → {s['fixed'][:20]:<20} {s['severity']}{kev}")
    print()

    if sample_dropped_no_exploit:
        print(f"📋 SAMPLE: DROPPED (Failed + Fix but no Exploit)")
        for s in sample_dropped_no_exploit:
            print(f"   {s['cve']:<18} {s['component']:<25} {s['severity']}")
        print()

    if sample_dropped_no_fix:
        print(f"📋 SAMPLE: DROPPED (Failed + Exploit but no Fix)")
        for s in sample_dropped_no_fix:
            print(f"   {s['cve']:<18} {s['component']:<25} {s['severity']}")
        print()

    if sample_dropped_neither:
        print(f"📋 SAMPLE: DROPPED (Failed but Neither Exploit nor Fix)")
        for s in sample_dropped_neither:
            print(f"   {s['cve']:<18} {s['component']:<25} {s['severity']}")
        print()

    # ============================================================
    # Write summary JSON for downstream
    # ============================================================
    summary = {
        "total_in_json": total,
        "failed_in_policy": failed,
        "failed_with_exploit": failed_with_exploit,
        "failed_with_fix": failed_with_fix,
        "failed_with_both": failed_with_both,
        "failed_with_neither": failed_with_neither,
        "failed_no_exploit_only": failed - failed_with_exploit,
        "failed_no_fix_only": failed - failed_with_fix,
        "would_keep_after_filter": failed_with_both,
        "severity_breakdown": dict(severity_counts),
        "sample_kept": sample_kept,
    }
    with open("filter_v2_diagnostic.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"💾 Full diagnostic saved to: filter_v2_diagnostic.json")
    print("=" * 80)
    print()
    print(f"📌 BOTTOM LINE")
    print(f"   New filter would produce: {failed_with_both} alerts in GitHub")
    print(f"   Customer mentioned: 'no exploit (123)' + 'no fix (44)' + 'both none (74)'")
    print(f"   Their math: 169 - 123 = 46 (or some variation)")
    print(f"   Our math:   {failed} - {failed - failed_with_both} = {failed_with_both}")
    print()


if __name__ == "__main__":
    main()
