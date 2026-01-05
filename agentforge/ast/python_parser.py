import ast
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

@dataclass
class ASTNodeMetadata:
    file_path: str
    line_no: int
    col_offset: int
    node_type: str
    name: str
    code_snippet: str
    taint_source: bool = False
    vulnerable_sink: bool = False

@dataclass
class CodebaseSymbolTable:
    functions: Dict[str, ASTNodeMetadata] = field(default_factory=dict)
    variables: Dict[str, ASTNodeMetadata] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)
    taint_chains: List[Tuple[str, str]] = field(default_factory=list)

class SecurityASTVisitor(ast.NodeVisitor):
    """
    AST Visitor extracting function definitions, variable assignments,
    and potential security taint propagation flows (sources to sinks).
    """
    TAINT_SOURCES = ["request.args", "request.form", "input", "sys.argv", "os.getenv"]
    VULNERABLE_SINKS = ["execute", "eval", "exec", "subprocess.call", "os.system", "open"]

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_lines = source_code.splitlines()
        self.symbol_table = CodebaseSymbolTable()
        self.nodes_visited: List[ASTNodeMetadata] = []

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        meta = ASTNodeMetadata(
            file_path=self.file_path,
            line_no=node.lineno,
            col_offset=node.col_offset,
            node_type="FunctionDef",
            name=node.name,
            code_snippet=self._get_snippet(node.lineno)
        )
        self.symbol_table.functions[node.name] = meta
        self.nodes_visited.append(meta)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        var_names = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_names.append(target.id)
        
        snippet = self._get_snippet(node.lineno)
        is_taint = any(src in snippet for src in self.TAINT_SOURCES)

        for name in var_names:
            meta = ASTNodeMetadata(
                file_path=self.file_path,
                line_no=node.lineno,
                col_offset=node.col_offset,
                node_type="Assign",
                name=name,
                code_snippet=snippet,
                taint_source=is_taint
            )
            self.symbol_table.variables[name] = meta
            self.nodes_visited.append(meta)
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        snippet = self._get_snippet(node.lineno)
        is_sink = func_name in self.VULNERABLE_SINKS or any(sink in snippet for sink in self.VULNERABLE_SINKS)

        if is_sink:
            meta = ASTNodeMetadata(
                file_path=self.file_path,
                line_no=node.lineno,
                col_offset=node.col_offset,
                node_type="Call",
                name=func_name,
                code_snippet=snippet,
                vulnerable_sink=True
            )
            self.nodes_visited.append(meta)

        self.generic_visit(node)


class PythonASTEngine:
    """
    High-level Python AST Parser engine for multi-file code auditing.
    """
    def parse_directory(self, target_dir: str) -> List[ASTNodeMetadata]:
        all_metadata = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        tree = ast.parse(content, filename=file_path)
                        visitor = SecurityASTVisitor(file_path, content)
                        visitor.visit(tree)
                        all_metadata.extend(visitor.nodes_visited)
                    except Exception:
                        pass
        return all_metadata
