"""
FlowGuard: A Mini Compiler-Based Security Analysis Tool
Taint-Tracking Static Analyzer Using Data-Flow Analysis.
"""

from flowguard.lexer import Lexer, Token, TokenType
from flowguard.parser import Parser
from flowguard.ast_nodes import ASTNode, ProgramNode
from flowguard.semantic import SemanticAnalyzer
from flowguard.cfg import CFGBuilder, ControlFlowGraph, BasicBlock
from flowguard.taint_engine import TaintAnalysisEngine, Vulnerability
from flowguard.analyzer import FlowGuardAnalyzer, AnalysisResult
from flowguard.report import ReportGenerator

__version__ = "1.0.0"
__all__ = [
    "Lexer",
    "Token",
    "TokenType",
    "Parser",
    "ASTNode",
    "ProgramNode",
    "SemanticAnalyzer",
    "CFGBuilder",
    "ControlFlowGraph",
    "BasicBlock",
    "TaintAnalysisEngine",
    "Vulnerability",
    "FlowGuardAnalyzer",
    "AnalysisResult",
    "ReportGenerator",
]
