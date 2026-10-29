"""
FlowGuard: Main Analysis Pipeline
Coordinates all 5 compiler stages:
Stage 1: Lexer (Tokenizing)
Stage 2: Parser (AST Construction)
Stage 3: Semantic Analysis (Symbol Table & Scopes)
Stage 4: CFG Builder (Basic Blocks & Edges)
Stage 5: Taint Engine (Worklist Algorithm to Fixpoint) & Report Generation
"""

from typing import Dict, Any, List, Optional
from flowguard.lexer import Lexer, Token
from flowguard.parser import Parser
from flowguard.ast_nodes import ProgramNode
from flowguard.semantic import SemanticAnalyzer, SemanticIssue
from flowguard.cfg import CFGBuilder, ControlFlowGraph
from flowguard.taint_engine import TaintAnalysisEngine, Vulnerability, WorklistIterationLog
from flowguard.report import ReportGenerator


class AnalysisResult:
    """Holds all artifacts from the 5 compiler pipeline stages."""
    def __init__(
        self,
        source_code: str,
        tokens: List[Token],
        ast: Optional[ProgramNode],
        semantic_issues: List[SemanticIssue],
        cfgs: Dict[str, ControlFlowGraph],
        vulnerabilities: List[Vulnerability],
        iteration_logs: List[WorklistIterationLog]
    ) -> None:
        self.source_code = source_code
        self.tokens = tokens
        self.ast = ast
        self.semantic_issues = semantic_issues
        self.cfgs = cfgs
        self.vulnerabilities = vulnerabilities
        self.iteration_logs = iteration_logs
        self.status = "failed" if any(i.severity == "ERROR" for i in semantic_issues) else "completed"
        self.stages = {}

    def get_terminal_report(self) -> str:
        if self.status == "failed":
            return "FLOWGUARD: Analysis failed due to diagnostics\n" + "\n".join(str(i) for i in self.semantic_issues)
        return ReportGenerator.generate_terminal_report(
            self.vulnerabilities,
            self.semantic_issues,
            self.source_code
        )

    def get_markdown_report(self) -> str:
        if self.status == "failed":
            return "# FlowGuard: Analysis failed\n" + "\n".join(str(i) for i in self.semantic_issues)
        return ReportGenerator.generate_markdown_report(self.vulnerabilities)

    def finding_details(self) -> List[Dict[str, Any]]:
        lines = self.source_code.splitlines()
        def excerpt(line: int) -> str:
            return lines[line - 1] if 0 < line <= len(lines) else ""
        details = []
        for finding in self.vulnerabilities:
            data = finding.to_dict()
            data["source_excerpt"] = excerpt(data["source_line"])
            data["sink_excerpt"] = excerpt(data["sink_line"])
            data["path"] = [dict(hop, code=excerpt(hop["line"])) for hop in data["path"]]
            details.append(data)
        return details

    def to_dict(self) -> Dict[str, Any]:
        main_cfg = self.cfgs.get("main")
        return {
            "status": self.status,
            "stages": self.stages,
            "findings": self.finding_details(),
            "diagnostics": [s.to_dict() for s in self.semantic_issues],
            "semantic_diagnostics": [s.to_dict() for s in self.semantic_issues if getattr(s, "stage", "semantic") == "semantic"],
            "statistics": {"tokens": len(self.tokens), "ast_nodes": count_ast(self.ast),
                           "cfg_blocks": sum(len(c.blocks) for c in self.cfgs.values()),
                           "findings": len(self.vulnerabilities), "worklist_steps": len(self.iteration_logs),
                           "converged": self.status == "completed"},
            "markdown_report": self.get_markdown_report(),
            "source_code": self.source_code,
            "tokens": [t.to_dict() for t in self.tokens],
            "ast": self.ast.to_dict() if self.ast else None,
            "semantic_issues": [s.to_dict() for s in self.semantic_issues],
            "cfgs": {name: cfg.to_dict() for name, cfg in self.cfgs.items()},
            "main_cfg_mermaid": main_cfg.to_mermaid() if main_cfg else "",
            "vulnerabilities": self.finding_details(),
            "iteration_logs": [log.to_dict() for log in self.iteration_logs],
            "report_summary": ReportGenerator.generate_json_report(
                self.vulnerabilities,
                self.semantic_issues,
                self.iteration_logs
            )
        }


def count_ast(root: Optional[ProgramNode]) -> int:
    from flowguard.ast_nodes import ASTNode
    pending = [root] if root else []
    total = 0
    while pending:
        node = pending.pop()
        total += 1
        for value in vars(node).values():
            if isinstance(value, ASTNode):
                pending.append(value)
            elif isinstance(value, list):
                pending.extend(v for v in value if isinstance(v, ASTNode))
    return total


class FlowGuardAnalyzer:
    """Pipeline with explicit stage status and bounded resource use."""
    def analyze(self, source_code: str) -> AnalysisResult:
        from flowguard.lexer import LexerError
        from flowguard.parser import ParserError
        from flowguard.taint_engine import AnalysisLimitError
        tokens, ast, issues, cfgs, findings, logs = [], None, [], {}, [], []
        stages = {s: "pending" for s in ("lex", "parse", "semantic", "cfg", "data_flow", "report")}
        stage = "lex"
        try:
            if not isinstance(source_code, str) or len(source_code) > 100000:
                raise ValueError("Source must be a string of at most 100000 characters")
            tokens = Lexer(source_code).tokenize()
            if len(tokens) > 10000:
                raise AnalysisLimitError("Source exceeds 10000 tokens")
            stages[stage] = "completed"
            stage = "parse"
            ast = Parser(tokens).parse()
            # Bound AST depth before recursive visitors and serialization.
            from flowguard.ast_nodes import ASTNode
            pending = [(ast, 0)]
            while pending:
                node, depth = pending.pop()
                if depth > 60:
                    ast = None
                    raise AnalysisLimitError("AST nesting exceeds 60 levels")
                for value in vars(node).values():
                    if isinstance(value, ASTNode):
                        pending.append((value, depth + 1))
                    elif isinstance(value, list):
                        pending.extend((v, depth + 1) for v in value if isinstance(v, ASTNode))
            stages[stage] = "completed"
            stage = "semantic"
            semantic = SemanticAnalyzer()
            issues = semantic.analyze(ast)
            if any(i.severity == "ERROR" for i in issues):
                stages[stage] = "failed"
            else:
                stages[stage] = "completed"
                stage = "cfg"
                cfgs = CFGBuilder().build_program_cfgs(ast)
                stages[stage] = "completed"
                stage = "data_flow"
                findings, logs = TaintAnalysisEngine(semantic.user_functions).analyze_cfg(cfgs["main"])
                stages[stage] = "completed"
                stages["report"] = "completed"
        except (LexerError, ParserError, AnalysisLimitError, ValueError, RecursionError) as error:
            message = "Program nesting exceeds analysis limits" if isinstance(error, RecursionError) else str(error)
            issue = SemanticIssue("ERROR", message, getattr(error, "line", 1), getattr(error, "col", 1))
            issue.stage = stage
            issues.append(issue)
            stages[stage] = "failed"
        result = AnalysisResult(source_code, tokens, ast, issues, cfgs, findings, logs)
        result.stages = stages
        return result
