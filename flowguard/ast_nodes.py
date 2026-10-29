"""
FlowGuard: AST Node Definitions
Represents the Abstract Syntax Tree (AST) constructed during Syntax Analysis (Module 2).
"""

from typing import List, Optional, Any, Dict

class ASTNode:
    """Base class for all AST nodes."""
    def __init__(self, line: int = 0, col: int = 0) -> None:
        self.line = line
        self.col = col

    def to_dict(self) -> Dict[str, Any]:
        """Convert AST node to dictionary for JSON serialization."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(line={self.line})"


class ProgramNode(ASTNode):
    """Root node representing the entire program."""
    def __init__(self, body: List[ASTNode], line: int = 1, col: int = 1) -> None:
        super().__init__(line, col)
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Program",
            "col": self.col, "line": self.line,
            "body": [stmt.to_dict() for stmt in self.body]
        }


class FunctionDefNode(ASTNode):
    """Represents a function definition: def name(params): body"""
    def __init__(self, name: str, params: List[str], body: List[ASTNode], line: int, col: int) -> None:
        super().__init__(line, col)
        self.name = name
        self.params = params
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "FunctionDef",
            "name": self.name,
            "params": self.params,
            "col": self.col, "line": self.line,
            "body": [stmt.to_dict() for stmt in self.body]
        }


class AssignNode(ASTNode):
    """Represents an assignment: target = value"""
    def __init__(self, target: str, value: ASTNode, line: int, col: int) -> None:
        super().__init__(line, col)
        self.target = target
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Assign",
            "target": self.target,
            "value": self.value.to_dict(),
            "col": self.col, "line": self.line
        }


class IfNode(ASTNode):
    """Represents an if-elif-else condition."""
    def __init__(self, condition: ASTNode, then_body: List[ASTNode], else_body: Optional[List[ASTNode]] = None, line: int = 0, col: int = 0) -> None:
        super().__init__(line, col)
        self.condition = condition
        self.then_body = then_body
        self.else_body = else_body or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "If",
            "condition": self.condition.to_dict(),
            "then_body": [stmt.to_dict() for stmt in self.then_body],
            "else_body": [stmt.to_dict() for stmt in self.else_body],
            "col": self.col, "line": self.line
        }


class WhileNode(ASTNode):
    """Represents a while loop: while condition: body"""
    def __init__(self, condition: ASTNode, body: List[ASTNode], line: int, col: int) -> None:
        super().__init__(line, col)
        self.condition = condition
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "While",
            "condition": self.condition.to_dict(),
            "body": [stmt.to_dict() for stmt in self.body],
            "col": self.col, "line": self.line
        }


class ReturnNode(ASTNode):
    """Represents a return statement: return value"""
    def __init__(self, value: Optional[ASTNode], line: int, col: int) -> None:
        super().__init__(line, col)
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Return",
            "value": self.value.to_dict() if self.value else None,
            "col": self.col, "line": self.line
        }


class PassNode(ASTNode):
    """Represents a pass statement."""
    def __init__(self, line: int, col: int) -> None:
        super().__init__(line, col)

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "Pass", "col": self.col, "line": self.line}


class ExprStmtNode(ASTNode):
    """Represents a standalone expression statement (like execute_query(query))."""
    def __init__(self, expr: ASTNode, line: int, col: int) -> None:
        super().__init__(line, col)
        self.expr = expr

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "ExprStmt",
            "expr": self.expr.to_dict(),
            "col": self.col, "line": self.line
        }


class BinaryOpNode(ASTNode):
    """Represents a binary operation: left op right"""
    def __init__(self, left: ASTNode, op: str, right: ASTNode, line: int, col: int) -> None:
        super().__init__(line, col)
        self.left = left
        self.op = op
        self.right = right

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "BinaryOp",
            "op": self.op,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
            "col": self.col, "line": self.line
        }


class UnaryOpNode(ASTNode):
    """Represents a unary operation: op operand (e.g. not x, -y)"""
    def __init__(self, op: str, operand: ASTNode, line: int, col: int) -> None:
        super().__init__(line, col)
        self.op = op
        self.operand = operand

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "UnaryOp",
            "op": self.op,
            "operand": self.operand.to_dict(),
            "col": self.col, "line": self.line
        }


class CallNode(ASTNode):
    """Represents a function call: func_name(arg1, arg2, ...)"""
    def __init__(self, callee: str, args: List[ASTNode], line: int, col: int) -> None:
        super().__init__(line, col)
        self.callee = callee
        self.args = args

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Call",
            "callee": self.callee,
            "args": [arg.to_dict() for arg in self.args],
            "col": self.col, "line": self.line
        }


class VarNode(ASTNode):
    """Represents a variable reference."""
    def __init__(self, name: str, line: int, col: int) -> None:
        super().__init__(line, col)
        self.name = name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Variable",
            "name": self.name,
            "col": self.col, "line": self.line
        }


class LiteralNode(ASTNode):
    """Represents a literal constant (int, float, string, bool, None)."""
    def __init__(self, value: Any, raw_type: str, line: int, col: int) -> None:
        super().__init__(line, col)
        self.value = value
        self.raw_type = raw_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Literal",
            "value": self.value,
            "raw_type": self.raw_type,
            "col": self.col, "line": self.line
        }
