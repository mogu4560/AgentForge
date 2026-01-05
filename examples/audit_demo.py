from agentforge import ASTCodeAuditor

def main():
    print("=== AgentForge Autonomous AST Code Auditing Agent Demo ===")
    auditor = ASTCodeAuditor(target_dir="./src")
    report = auditor.run_audit()

    print(f"\nAudit complete. Scanned {report.files_scanned} files.")
    print(f"Discovered {len(report.vulnerabilities)} vulnerabilities:")

    for v in report.vulnerabilities:
        print(f"\n--------------------------------------------------")
        print(f"🚨 [{v.severity}] {v.title}")
        print(f"Location: {v.file_path}:L{v.line_number}")
        print(f"Suggested Refactor Fix:\n{v.suggested_fix}")

if __name__ == "__main__":
    main()
