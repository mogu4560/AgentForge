from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from agentforge.security.rule_engine import SecurityFinding

@dataclass
class RefactorPatch:
    finding_id: str
    file_path: str
    original_code: str
    suggested_code: str
    diff_patch: str
    reasoning: str

class LlamaReasoningAgent:
    """
    Simulated LlamaIndex Agentic Loop using Llama-3 for security vulnerability
    triage, contextual reasoning, and refactored code patch synthesis.
    """
    PROMPT_TEMPLATE = """
    [SYSTEM SECURITY PROMPT]
    You are an expert AST code auditing agent powered by Llama-3. Analyze the following security finding:
    Rule: {rule_id} ({title})
    Severity: {severity} | CWE: {cwe_id}
    File: {file_path}:{line_no}
    Snippet: `{snippet}`

    Synthesize a clean, production-ready refactored fix and unified git diff patch.
    """

    def __init__(self, model_name: str = "llama3-70b-instruct"):
        self.model_name = model_name

    def generate_diff(self, original: str, fixed: str, file_path: str) -> str:
        return f"--- {file_path}\n+++ {file_path}\n@@ -1,1 +1,1 @@\n- {original}\n+ {fixed}"

    def synthesize_fixes(self, findings: List[SecurityFinding]) -> List[RefactorPatch]:
        patches = []
        for finding in findings:
            snippet = finding.code_snippet
            file_path = finding.file_path

            if "SQL" in finding.title or "SEC-001" in finding.rule_id:
                suggested = "cursor.execute('SELECT * FROM users WHERE username = %s', (user_input,))"
                reasoning = "Replaced unsafe string interpolation with parameterized SQL query placeholder."
            elif "Secret" in finding.title or "SEC-002" in finding.rule_id:
                suggested = "api_key = os.getenv('SECRET_API_KEY')"
                reasoning = "Replaced hardcoded API key string with environment variable lookup."
            elif "Command" in finding.title or "SEC-003" in finding.rule_id:
                suggested = "subprocess.run(['ls', '-l'], check=True)"
                reasoning = "Replaced os.system with subprocess.run using a tokenized argument array."
            else:
                suggested = f"# [SEC FIX]: {snippet}"
                reasoning = "Applied automated security sanitization wrapper."

            diff = self.generate_diff(snippet, suggested, file_path)
            
            patches.append(RefactorPatch(
                finding_id=finding.rule_id,
                file_path=file_path,
                original_code=snippet,
                suggested_code=suggested,
                diff_patch=diff,
                reasoning=reasoning
            ))

        return patches
