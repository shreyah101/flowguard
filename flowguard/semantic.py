"""
FlowGuard: Semantic Analyzer (Module 3 - Semantic Analysis)
Validates scope rules (use-before-def), maintains symbol tables,
and classifies functions into Sources, Sinks, and Sanitizers.
"""

from typing import Dict, List, Set, Optional, Any
from flowguard.ast_nodes import (
    ASTNode, ProgramNode, FunctionDefNode, AssignNode,
    IfNode, WhileNode, ReturnNode, PassNode, ExprStmtNode,
    BinaryOpNode, UnaryOpNode, CallNode, VarNode, LiteralNode
)


class Symbol:
    def __init__(self, name: str, sym_type: str, line: int) -> None:
        self.name = name
        self.sym_type = sym_type  # 'variable', 'function', 'parameter'
        self.line = line


class SymbolTable:
    def __init__(self, parent: Optional['SymbolTable'] = None, scope_name: str = "global") -> None:
        self.parent = parent
        self.scope_name = scope_name
        self.symbols: Dict[str, Symbol] = {}

    def define(self, name: str, sym_type: str, line: int) -> None:
        self.symbols[name] = Symbol(name, sym_type, line)

    def lookup(self, name: str) -> Optional[Symbol]:
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

    def is_defined(self, name: str) -> bool:
        return self.lookup(name) is not None


class SemanticIssue:
    def __init__(self, severity: str, message: str, line: int, col: int = 1) -> None:
        self.severity = severity  # "ERROR", "WARNING", "INFO"
        self.message = message
        self.line = line
        self.col = col

    def __repr__(self) -> str:
        return f"[{self.severity}] Line {self.line}: {self.message}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": getattr(self, "stage", "semantic"),
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "col": self.col
        }


# Security Definitions
KNOWN_SOURCES = {
    "input": "Generic User Input",
    "request_get": "HTTP GET Parameter",
    "request_post": "HTTP POST Body",
    "get_user_input": "Interactive User Input",
    "read_query_param": "URL Query Parameter",
    "get_env": "Environment Variable",
    "read_cookie": "User Cookie Data"
}

KNOWN_SINKS = {
    "execute_query": {"type": "SQL Injection", "severity": "HIGH", "desc": "Executes raw database query with tainted input"},
    "system": {"type": "Command Injection", "severity": "CRITICAL", "desc": "Executes shell command with untrusted input"},
    "popen": {"type": "Command Injection", "severity": "CRITICAL", "desc": "Spawns process with untrusted input"},
    "eval": {"type": "Code Injection", "severity": "CRITICAL", "desc": "Evaluates untrusted string as code"},
    "exec": {"type": "Code Injection", "severity": "CRITICAL", "desc": "Executes arbitrary string as code"},
    "write_file": {"type": "Path Traversal / Arbitrary File Write", "severity": "HIGH", "desc": "Writes untrusted data to file system"},
    "render_html": {"type": "Cross-Site Scripting (XSS)", "severity": "MEDIUM", "desc": "Renders unescaped user data to HTML output"}
}

KNOWN_SANITIZERS = {
    "sanitize": "Generic Sanitizer",
    "escape": "String Escape",
    "escape_sql": "SQL Escape Function",
    "int": "Typecast to Integer (Safe numeric filter)",
    "float": "Typecast to Float (Safe numeric filter)",
    "html_escape": "HTML Entity Encoder",
    "whitelist": "Allowlist Validator"
}


# Sanitizers remove only the explicitly modeled risk categories.
KNOWN_SOURCES.update({"read_user_input": "User input", "get_request_param": "Request parameter"})
KNOWN_SINKS["run_command"] = dict(KNOWN_SINKS["system"])
SANITIZER_CONTEXTS = {
    "sanitize": {"SQL Injection"}, "escape": {"SQL Injection"},
    "escape_sql": {"SQL Injection"}, "sanitize_sql": {"SQL Injection"},
    "sanitize_command": {"Command Injection"},
    "sanitize_path": {"Path Traversal / Arbitrary File Write"},
    "html_escape": {"Cross-Site Scripting (XSS)"},
    "int": {info["type"] for info in KNOWN_SINKS.values()},
    "float": {info["type"] for info in KNOWN_SINKS.values()},
    # An unspecified allowlist has no universal security guarantee.
    "whitelist": set(),
}
KNOWN_SANITIZERS.update({name: "Modeled context sanitizer" for name in SANITIZER_CONTEXTS})
BUILTIN_ARITY = {name: (0, 1) for name in KNOWN_SOURCES}
BUILTIN_ARITY.update({name: (1, 1) for name in KNOWN_SANITIZERS})
BUILTIN_ARITY.update({name: (1, 1) for name in KNOWN_SINKS})
BUILTIN_ARITY.update({"write_file": (2, 2), "print": (0, 100), "len": (1, 1), "str": (1, 1), "range": (1, 3)})
# Both path and content are sensitive in this educational file-write policy.
SENSITIVE_ARGUMENTS = {name: (0,) for name in KNOWN_SINKS}
SENSITIVE_ARGUMENTS["write_file"] = (0, 1)


class SemanticAnalyzer:
    """Definite assignment uses intersection at joins; types have an Unknown top."""
    def __init__(self) -> None:
        self.issues: List[SemanticIssue] = []
        self.user_functions: Dict[str, FunctionDefNode] = {}
        self.global_table = SymbolTable()

    def issue(self, node: ASTNode, message: str, severity: str = "ERROR") -> None:
        self.issues.append(SemanticIssue(severity, message, node.line, node.col))

    def analyze(self, root: ProgramNode) -> List[SemanticIssue]:
        self.issues = []
        self.user_functions = {}
        for node in root.body:
            if isinstance(node, FunctionDefNode):
                if node.name in self.user_functions or node.name in BUILTIN_ARITY:
                    self.issue(node, f"Duplicate or conflicting function '{node.name}'")
                self.user_functions[node.name] = node
                if len(set(node.params)) != len(node.params):
                    self.issue(node, "Duplicate parameter names")
        self.block(root.body, {}, False, top_level=True)
        for fn in self.user_functions.values():
            if any(p in BUILTIN_ARITY or p in self.user_functions for p in fn.params):
                self.issue(fn, "Parameters cannot shadow function names in FlowGuard")
            self.block(fn.body, {p: "Unknown" for p in fn.params}, True)
        return self.issues

    def block(self, nodes: List[ASTNode], env: Dict[str, str], in_function: bool, top_level: bool = False) -> bool:
        """Mutate a definite-assignment environment; return whether control continues."""
        for node in nodes:
            if isinstance(node, FunctionDefNode):
                if not top_level:
                    self.issue(node, "Nested function definitions are unsupported")
            elif isinstance(node, AssignNode):
                if node.target in BUILTIN_ARITY or node.target in self.user_functions:
                    self.issue(node, "Assignments cannot shadow function names in FlowGuard")
                env[node.target] = self.expr(node.value, env)
            elif isinstance(node, (IfNode, WhileNode)):
                self.expr(node.condition, env)
                left, right = dict(env), dict(env)
                continues_left = self.block(node.then_body if isinstance(node, IfNode) else node.body, left, in_function)
                if isinstance(node, IfNode):
                    continues_right = self.block(node.else_body, right, in_function)
                    if not continues_left and not continues_right:
                        return False
                    merged = right if not continues_left else left if not continues_right else {
                        k: left[k] if left[k] == right[k] else "Unknown" for k in left.keys() & right.keys()}
                    env.clear()
                    env.update(merged)
                else:
                    for k in env:
                        if env[k] != left.get(k):
                            env[k] = "Unknown"
            elif isinstance(node, ReturnNode):
                if not in_function:
                    self.issue(node, "Return statement outside a function")
                if node.value:
                    self.expr(node.value, env)
                return False
            elif isinstance(node, ExprStmtNode):
                self.expr(node.expr, env)
        return True

    def expr(self, node: ASTNode, env: Dict[str, str]) -> str:
        if isinstance(node, LiteralNode):
            return node.raw_type
        if isinstance(node, VarNode):
            if node.name not in env:
                self.issue(node, f"Variable '{node.name}' may be used before assignment")
            return env.get(node.name, "Unknown")
        if isinstance(node, CallNode):
            for arg in node.args:
                self.expr(arg, env)
            if node.callee in self.user_functions:
                arity = len(self.user_functions[node.callee].params)
                limits = (arity, arity)
            else:
                limits = BUILTIN_ARITY.get(node.callee)
            if limits is None:
                self.issue(node, f"Undefined function '{node.callee}()'")
            elif not limits[0] <= len(node.args) <= limits[1]:
                self.issue(node, f"Function '{node.callee}' expects {limits[0]}..{limits[1]} arguments; got {len(node.args)}")
            return "Unknown"
        if isinstance(node, UnaryOpNode):
            t = self.expr(node.operand, env)
            return "bool" if node.op == "not" else t
        if isinstance(node, BinaryOpNode):
            left, right = self.expr(node.left, env), self.expr(node.right, env)
            if node.op in ("==", "!=", "<", ">", "<=", ">="):
                return "bool"
            if node.op in ("and", "or"):
                return left if left == right else "Unknown"
            if "Unknown" not in (left, right):
                numeric = {left, right} <= {"int", "float", "bool"}
                if not numeric and not (node.op == "+" and left == right == "str"):
                    self.issue(node, f"Possibly incompatible operand types: {left} {node.op} {right}", "WARNING")
                return left if left == right else "Unknown"
        return "Unknown"
