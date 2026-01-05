import pytest
from agentforge.ast.python_parser import PythonASTEngine, SecurityASTVisitor
from agentforge.security.rule_engine import SecurityRuleEngine, SecurityFinding
from agentforge.llm.reasoning_agent import LlamaReasoningAgent

SAMPLE_CODE = """
import os
import sqlite3

def handle_request(user_input):
    api_key = "secret_12345678"
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    os.system("echo hello")
"""

def test_ast_visitor():
    visitor = SecurityASTVisitor("test.py", SAMPLE_CODE)
    import ast
    tree = ast.parse(SAMPLE_CODE)
    visitor.visit(tree)
    assert len(visitor.nodes_visited) >= 3

def test_rule_engine():
    engine = SecurityRuleEngine()
    visitor = SecurityASTVisitor("test.py", SAMPLE_CODE)
    import ast
    tree = ast.parse(SAMPLE_CODE)
    visitor.visit(tree)
    findings = engine.evaluate_nodes(visitor.nodes_visited)
    assert len(findings) >= 2
    severities = [f.severity for f in findings]
    assert "CRITICAL" in severities or "HIGH" in severities

def test_reasoning_agent():
    agent = LlamaReasoningAgent()
    finding = SecurityFinding(
        rule_id="SEC-001",
        title="SQL Injection",
        severity="HIGH",
        file_path="test.py",
        line_number=9,
        code_snippet="cursor.execute(query)",
        cwe_id="CWE-89",
        remediation_guidance="Use parameterized queries"
    )
    patches = agent.synthesize_fixes([finding])
    assert len(patches) == 1
    assert "parameterized" in patches[0].reasoning.lower()
