# AgentForge: Autonomous AST-Based Code Auditing Agent

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![LlamaIndex](https://img.shields.io/badge/LlamaIndex-0.9%2B-purple.svg)](https://llamaindex.ai)
[![Tree--Sitter](https://img.shields.io/badge/Tree--Sitter-AST_Parser-orange.svg)](https://tree-sitter.github.io)
[![Llama-3](https://img.shields.io/badge/Llama--3-Reasoning_Engine-green.svg)](https://meta.com)

AgentForge is an autonomous code auditing and refactoring agent powered by LlamaIndex, Tree-Sitter Abstract Syntax Tree (AST) parsing, and Llama-3. It traverses complex multi-file codebases, constructs semantic AST node maps, detects security vulnerabilities (SQL injection, hardcoded secrets, memory leaks), and outputs automated pull-request refactoring fixes.

---

## Key Features

- **AST-Guided Analysis:** Replaces naive regex scanning with Tree-Sitter AST parsing to understand variable scope, control flow, and taint propagation.
- **Autonomous LLM Loop:** Uses LlamaIndex agentic reasoning to query codebase graphs and generate context-aware patch recommendations.
- **Rule-Engine Configurable:** Custom YAML security rules for domain-specific static analysis policies.
- **Automated Fixes:** Generates unified diffs and refactored code snippets ready for PR review.

---

## Quick Start

### Installation

```bash
git clone https://github.com//AgentForge.git
cd AgentForge
pip install -r requirements.txt
```

### Usage

```python
from agentforge import ASTCodeAuditor

# Initialize auditor targeting a local repository directory
auditor = ASTCodeAuditor(target_dir="./src", rules_config="config/rules.yaml")

# Run autonomous vulnerability scan and refactoring synthesis
report = auditor.run_audit()

print(f"Total Files Audited: {report.files_scanned}")
print(f"Vulnerabilities Found: {len(report.vulnerabilities)}")

for vuln in report.vulnerabilities:
    print(f"\n🚨 [{vuln.severity}] {vuln.title} in {vuln.file_path}:{vuln.line_number}")
    print(f"Suggested Refactor Fix:\n{vuln.suggested_fix}")
```

---

## Architecture Flowchart

```text
Target Codebase ──► Tree-Sitter Parser ──► AST Node Graph ──► LlamaIndex Query Index
                                                                   │
                                                                   ▼
                                                            Llama-3 Reasoning Agent
                                                                   │
                                                                   ▼
                                                            Refactor Patch & Report
```

---
