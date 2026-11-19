#!/usr/bin/env python3
"""
Kubernetes Security Linter for AI Workloads (v1.0.0).

Inspects Kubernetes YAML manifests to detect dangerous configurations that bypass
AWS IMDSv2 metadata protections or break container sandboxing:
1. hostNetwork: true (Bypasses IMDSv2 HttpPutResponseHopLimit=1 by sharing host namespace)
2. securityContext.privileged: true (Breaks container isolation; root host compromise)
3. hostPID: true / hostIPC: true (Exposes host process table / IPC mechanisms)
4. allowPrivilegeEscalation: true (Permits privilege escalation within AI container)
5. Dangerous hostPath volume mounts (Direct host filesystem access)
"""

import argparse
import re
import sys
from pathlib import Path

SECURITY_RULES = [
    {
        "id": "SEC-K8S-001",
        "name": "HostNetwork Misconfiguration",
        "severity": "CRITICAL",
        "pattern": re.compile(r"^\s*hostNetwork:\s*true\b", re.MULTILINE | re.IGNORECASE),
        "message": "hostNetwork: true detected! This allows the AI pod to share the host network namespace, completely bypassing AWS IMDSv2 HttpPutResponseHopLimit=1 metadata protection.",
    },
    {
        "id": "SEC-K8S-002",
        "name": "Privileged Container Misconfiguration",
        "severity": "CRITICAL",
        "pattern": re.compile(r"^\s*privileged:\s*true\b", re.MULTILINE | re.IGNORECASE),
        "message": "securityContext.privileged: true detected! Privileged AI workloads can access host kernel devices and compromise cluster nodes.",
    },
    {
        "id": "SEC-K8S-003",
        "name": "HostPID / HostIPC Exposure",
        "severity": "HIGH",
        "pattern": re.compile(r"^\s*(hostPID|hostIPC):\s*true\b", re.MULTILINE | re.IGNORECASE),
        "message": "hostPID or hostIPC set to true. Workload can snoop on host processes or inter-process communication.",
    },
    {
        "id": "SEC-K8S-004",
        "name": "Privilege Escalation Allowed",
        "severity": "HIGH",
        "pattern": re.compile(r"^\s*allowPrivilegeEscalation:\s*true\b", re.MULTILINE | re.IGNORECASE),
        "message": "allowPrivilegeEscalation: true detected. Child processes can acquire additional capabilities beyond container spec.",
    },
    {
        "id": "SEC-K8S-005",
        "name": "Insecure HostPath Volume Mount",
        "severity": "HIGH",
        "pattern": re.compile(r"^\s*hostPath:\s*$", re.MULTILINE | re.IGNORECASE),
        "message": "hostPath volume detected. AI workloads must never mount host directories directly.",
    },
]


def lint_manifest_file(file_path: Path) -> list[dict[str, str]]:
    """Scans a single YAML manifest against security rules."""
    violations = []
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        violations.append({
            "rule_id": "ERR-READ",
            "name": "File Read Error",
            "severity": "ERROR",
            "message": f"Could not read manifest file: {exc}",
            "file": str(file_path),
            "line": 0,
        })
        return violations

    lines = content.splitlines()
    for rule in SECURITY_RULES:
        for idx, line in enumerate(lines, start=1):
            if rule["pattern"].search(line):
                violations.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "file": str(file_path),
                    "line": idx,
                    "matched_line": line.strip(),
                })
    return violations


def scan_directory_or_files(target_paths: list[str]) -> tuple[int, int, list[dict[str, str]]]:
    """Scans all YAML files under target paths."""
    all_violations = []
    scanned_count = 0

    files_to_scan = []
    for target in target_paths:
        p = Path(target)
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml"):
            files_to_scan.append(p)
        elif p.is_dir():
            for ext in ("*.yaml", "*.yml"):
                files_to_scan.extend(p.glob(f"**/{ext}"))

    files_to_scan = sorted(set(files_to_scan))
    for f in files_to_scan:
        scanned_count += 1
        violations = lint_manifest_file(f)
        all_violations.extend(violations)

    return scanned_count, len(all_violations), all_violations


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Security Linter for AI Workloads")
    parser.add_argument(
        "targets",
        nargs="*",
        default=["infra"],
        help="Files or directories to scan (defaults to 'infra')",
    )
    args = parser.parse_args()

    print("=" * 80)
    print(" KUBERNETES MANIFEST SECURITY LINTER (SHADOW AI GOVERNANCE LAB)")
    print("=" * 80)

    scanned_count, violation_count, violations = scan_directory_or_files(args.targets)

    print(f"[*] Scanned Manifest Files: {scanned_count}")
    print(f"[*] Total Security Violations: {violation_count}\n")

    if violation_count == 0:
        print("[+] SUCCESS: All Kubernetes manifests passed security linting!")
        print("    - hostNetwork is false across all AI workload manifests.")
        print("    - No privileged containers or dangerous hostPath mounts detected.")
        print("    - IMDSv2 Hop Limit = 1 network boundary is preserved.")
        print("=" * 80)
        sys.exit(0)
    else:
        print("[-] FAILED: Security violations detected in Kubernetes manifests:")
        for v in violations:
            print(f"  [{v['severity']}] {v['rule_id']} - {v['name']}")
            print(f"    File: {v['file']}:{v['line']}")
            if "matched_line" in v:
                print(f"    Code: {v['matched_line']}")
            print(f"    Details: {v['message']}\n")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
