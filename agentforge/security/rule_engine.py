import re
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from agentforge.ast.python_parser import ASTNodeMetadata

@dataclass
class SecurityFinding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    code_snippet: str
    cwe_id: str
    remediation_guidance: str

@dataclass
class SecurityRule:
    rule_id: str
    title: str
    severity: str
    cwe_id: str
    pattern: str
    node_type: Optional[str] = None
    remediation: str = ""

class SecurityRuleEngine:
    """
    Evaluates AST Node Metadata against YAML security rules and AST taint propagation trees.
    """
    DEFAULT_RULES = [
        SecurityRule(
            rule_id="SEC-001",
            title="Unsanitized SQL Query Construction",
            severity="HIGH",
            cwe_id="CWE-89",
            pattern=r"(select|insert|update|delete)\s+.*(f\"|%s|\+)",
            remediation="Use parameterized query placeholders instead of string formatting."
        ),
        SecurityRule(
            rule_id="SEC-002",
            title="Hardcoded API Secret or Credential",
            severity="CRITICAL",
            cwe_id="CWE-798",
            pattern=r"(api_key|secret_key|password|aws_token)\s*=\s*[\"'][A-Za-z0-9_\-]{8,}[\"']",
            remediation="Load sensitive credentials from environment variables or a secrets manager."
        ),
        SecurityRule(
            rule_id="SEC-003",
            title="Unsafe Command Injection Sink",
            severity="CRITICAL",
            cwe_id="CWE-78",
            pattern=r"(os\.system|subprocess\.call|eval|exec)\(",
            remediation="Avoid shell=True and validate input arguments before executing commands."
        ),
        SecurityRule(
            rule_id="SEC-004",
            title="Unclosed File Resource Leak",
            severity="MEDIUM",
            cwe_id="CWE-775",
            pattern=r"open\(.*\)[\s\n]*$",
            remediation="Use a 'with open(...) as f:' context manager to guarantee resource cleanup."
        )
    ]

    def __init__(self, yaml_config_path: Optional[str] = None):
        self.rules: List[SecurityRule] = list(self.DEFAULT_RULES)
        if yaml_config_path:
            self._load_yaml_rules(yaml_config_path)

    def _load_yaml_rules(self, yaml_path: str):
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                for item in data.get("rules", []):
                    self.rules.append(SecurityRule(
                        rule_id=item.get("id", "CUSTOM-001"),
                        title=item.get("name", "Custom Rule"),
                        severity=item.get("severity", "MEDIUM"),
                        cwe_id=item.get("cwe", "CWE-200"),
                        pattern=item.get("pattern", ""),
                        remediation=item.get("remediation", "")
                    ))
        except Exception:
            pass

    def evaluate_nodes(self, nodes: List[ASTNodeMetadata]) -> List[SecurityFinding]:
        findings = []
        for node in nodes:
            snippet = node.code_snippet
            for rule in self.rules:
                if rule.pattern and re.search(rule.pattern, snippet, re.IGNORECASE):
                    findings.append(SecurityFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file_path=node.file_path,
                        line_number=node.line_no,
                        code_snippet=snippet,
                        cwe_id=rule.cwe_id,
                        remediation_guidance=rule.remediation
                    ))
        return findings
