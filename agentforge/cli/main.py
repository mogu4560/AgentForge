import os
import sys
import json
import argparse
from typing import List, Dict, Any
from agentforge.ast.python_parser import PythonASTEngine
from agentforge.security.rule_engine import SecurityRuleEngine, SecurityFinding
from agentforge.llm.reasoning_agent import LlamaReasoningAgent

class AgentForgeCLI:
    """
    CLI orchestrator for AgentForge autonomous code auditing.
    Supports SARIF (Static Analysis Results Interchange Format) output.
    """
    def __init__(self, target_dir: str, rules_path: str = None):
        self.target_dir = target_dir
        self.ast_engine = PythonASTEngine()
        self.rule_engine = SecurityRuleEngine(rules_path)
        self.agent = LlamaReasoningAgent()

    def export_sarif(self, findings: List[SecurityFinding], output_file: str = "results.sarif"):
        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AgentForge",
                        "version": "1.0.0",
                        "rules": [{"id": f.rule_id, "shortDescription": {"text": f.title}} for f in findings]
                    }
                },
                "results": [{
                    "ruleId": f.rule_id,
                    "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning",
                    "message": {"text": f.title},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line_number}
                        }
                    }]
                } for f in findings]
            }]
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
        print(f"📄 Exported SARIF security report to {output_file}")

    def run(self):
        print(f"🔍 Starting AgentForge AST Security Scan on directory: '{self.target_dir}'...")
        nodes = self.ast_engine.parse_directory(self.target_dir)
        print(f"📊 Parsed {len(nodes)} AST nodes across codebase.")

        findings = self.rule_engine.evaluate_nodes(nodes)
        print(f"🚨 Identified {len(findings)} security findings.")

        patches = self.agent.synthesize_fixes(findings)
        
        for idx, (f, p) in enumerate(zip(findings, patches)):
            print(f"\n[{idx+1}] [{f.severity}] {f.title} ({f.rule_id})")
            print(f"    File: {f.file_path}:{f.line_number}")
            print(f"    Snippet: `{f.code_snippet}`")
            print(f"    Patch Reasoning: {p.reasoning}")
            print(f"    Suggested Fix:\n    {p.suggested_code}")

        self.export_sarif(findings)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentForge Autonomous AST Code Auditor")
    parser.add_argument("--dir", type=str, default="./src", help="Target source code directory")
    args = parser.parse_args()
    
    cli = AgentForgeCLI(args.dir)
    cli.run()
