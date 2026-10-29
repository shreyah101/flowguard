"""
FlowGuard: Syntax Analyzer / Parser (Module 2 - Syntax Analysis)
Constructs an Abstract Syntax Tree (AST) using Recursive Descent Parsing.
Validates the grammar of the Python-like security domain language.
"""

from typing import List, Optional
from flowguard.lexer import Token, TokenType
from flowguard.ast_nodes import (
    ASTNode, ProgramNode, FunctionDefNode, AssignNode,
    IfNode, WhileNode, ReturnNode, PassNode, ExprStmtNode,
    BinaryOpNode, UnaryOpNode, CallNode, VarNode, LiteralNode
)


class ParserError(Exception):
    def __init__(self, message: str, token: Optional[Token] = None) -> None:
        if token:
            super().__init__(f"ParserError [Line {token.line}, Col {token.col}]: {message} (got {token.type.name} {repr(token.value)})")
            self.line = token.line
            self.col = token.col
        else:
            super().__init__(f"ParserError: {message}")
            self.line = 0
            self.col = 0


class Parser:
    """Recursive Descent Parser for FlowGuard simplified language."""
    def __init__(self, tokens: List[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def current_token(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]

    def peek_token(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]

    def match(self, *expected_types: TokenType) -> bool:
        return self.current_token().type in expected_types

    def consume(self, expected_type: TokenType, err_msg: Optional[str] = None) -> Token:
        token = self.current_token()
        if token.type == expected_type:
            self.pos += 1
            return token
        msg = err_msg or f"Expected token {expected_type.name}"
        raise ParserError(msg, token)

    def skip_newlines(self) -> None:
        while self.match(TokenType.NEWLINE):
            self.pos += 1

    def parse(self) -> ProgramNode:
        """Top-level parser entry point."""
        self.skip_newlines()
        statements = []
        while not self.match(TokenType.EOF):
            stmt = self.statement()
            if stmt:
                statements.append(stmt)
            self.skip_newlines()
        return ProgramNode(body=statements, line=1, col=1)

    def statement(self) -> ASTNode:
        token = self.current_token()

        if token.type == TokenType.DEF:
            return self.function_def()
        elif token.type == TokenType.IF:
            return self.if_statement()
        elif token.type == TokenType.WHILE:
            return self.while_statement()
        elif token.type == TokenType.RETURN:
            return self.return_statement()
        elif token.type == TokenType.PASS:
            self.consume(TokenType.PASS)
            self.consume_statement_end()
            return PassNode(line=token.line, col=token.col)
        else:
            return self.assign_or_expr_statement()

    def consume_statement_end(self) -> None:
        """A statement ends with a NEWLINE, EOF, or DEDENT."""
        if self.match(TokenType.NEWLINE):
            self.consume(TokenType.NEWLINE)
        elif self.match(TokenType.EOF, TokenType.DEDENT):
            pass
        else:
            raise ParserError("Expected newline after statement", self.current_token())

    def suite(self) -> List[ASTNode]:
        """Parses an indented suite: NEWLINE INDENT stmt+ DEDENT."""
        self.consume(TokenType.COLON, "Expected ':' before code block")

        # Check if suite is on the same line or indented block
        if self.match(TokenType.NEWLINE):
            self.consume(TokenType.NEWLINE)
            self.skip_newlines()
            self.consume(TokenType.INDENT, "Expected indented block")
            stmts = []
            while not self.match(TokenType.DEDENT, TokenType.EOF):
                self.skip_newlines()
                if self.match(TokenType.DEDENT, TokenType.EOF):
                    break
                s = self.statement()
                if s:
                    stmts.append(s)
                self.skip_newlines()
            self.consume(TokenType.DEDENT, "Expected un-indent (DEDENT)")
            return stmts
        else:
            # Inline suite like: if x: y = 1
            s = self.statement()
            return [s]

    def function_def(self) -> FunctionDefNode:
        start_tok = self.consume(TokenType.DEF)
        name_tok = self.consume(TokenType.IDENTIFIER, "Expected function name")
        self.consume(TokenType.LPAREN, "Expected '(' after function name")
        params = []
        if not self.match(TokenType.RPAREN):
            param_tok = self.consume(TokenType.IDENTIFIER, "Expected parameter name")
            params.append(param_tok.value)
            while self.match(TokenType.COMMA):
                self.consume(TokenType.COMMA)
                param_tok = self.consume(TokenType.IDENTIFIER, "Expected parameter name")
                params.append(param_tok.value)
        self.consume(TokenType.RPAREN, "Expected ')' after parameters")
        body = self.suite()
        return FunctionDefNode(name=name_tok.value, params=params, body=body, line=start_tok.line, col=start_tok.col)

    def if_statement(self) -> IfNode:
        start_tok = self.current_token()
        self.consume(start_tok.type if start_tok.type == TokenType.ELIF else TokenType.IF)
        condition = self.expression()
        then_body = self.suite()
        else_body = []

        self.skip_newlines()
        if self.match(TokenType.ELIF):
            # Parse ELIF recursively as nested IF in else_body
            nested_elif = self.if_statement()
            else_body = [nested_elif]
        elif self.match(TokenType.ELSE):
            self.consume(TokenType.ELSE)
            else_body = self.suite()

        return IfNode(condition=condition, then_body=then_body, else_body=else_body, line=start_tok.line, col=start_tok.col)

    def while_statement(self) -> WhileNode:
        start_tok = self.consume(TokenType.WHILE)
        condition = self.expression()
        body = self.suite()
        return WhileNode(condition=condition, body=body, line=start_tok.line, col=start_tok.col)

    def return_statement(self) -> ReturnNode:
        tok = self.consume(TokenType.RETURN)
        val = None
        if not self.match(TokenType.NEWLINE, TokenType.EOF, TokenType.DEDENT):
            val = self.expression()
        self.consume_statement_end()
        return ReturnNode(value=val, line=tok.line, col=tok.col)

    def assign_or_expr_statement(self) -> ASTNode:
        """Parses variable assignments (x = expr) or standalone expressions (func_call())."""
        # Lookahead: if IDENTIFIER followed by '=', it's an assignment!
        if self.match(TokenType.IDENTIFIER) and self.peek_token(1).type == TokenType.EQUALS:
            var_tok = self.consume(TokenType.IDENTIFIER)
            self.consume(TokenType.EQUALS)
            value = self.expression()
            self.consume_statement_end()
            return AssignNode(target=var_tok.value, value=value, line=var_tok.line, col=var_tok.col)

        expr = self.expression()
        self.consume_statement_end()
        return ExprStmtNode(expr=expr, line=expr.line, col=expr.col)

    # ---------------- Expression Parsing (Precedence) ----------------

    def expression(self) -> ASTNode:
        return self.logic_or()

    def logic_or(self) -> ASTNode:
        left = self.logic_and()
        while self.match(TokenType.OR):
            op_tok = self.consume(TokenType.OR)
            right = self.logic_and()
            left = BinaryOpNode(left=left, op="or", right=right, line=op_tok.line, col=op_tok.col)
        return left

    def logic_and(self) -> ASTNode:
        left = self.logic_not()
        while self.match(TokenType.AND):
            op_tok = self.consume(TokenType.AND)
            right = self.logic_not()
            left = BinaryOpNode(left=left, op="and", right=right, line=op_tok.line, col=op_tok.col)
        return left

    def logic_not(self) -> ASTNode:
        if self.match(TokenType.NOT):
            op_tok = self.consume(TokenType.NOT)
            operand = self.logic_not()
            return UnaryOpNode(op="not", operand=operand, line=op_tok.line, col=op_tok.col)
        return self.comparison()

    def comparison(self) -> ASTNode:
        left = self.additive()
        comp_ops = {
            TokenType.EQEQ: "==",
            TokenType.NOTEQ: "!=",
            TokenType.LT: "<",
            TokenType.LTE: "<=",
            TokenType.GT: ">",
            TokenType.GTE: ">="
        }
        while self.current_token().type in comp_ops:
            tok = self.current_token()
            self.pos += 1
            right = self.additive()
            left = BinaryOpNode(left=left, op=comp_ops[tok.type], right=right, line=tok.line, col=tok.col)
            if self.current_token().type in comp_ops:
                raise ParserError("Chained comparisons are unsupported; use explicit and", self.current_token())
        return left

    def additive(self) -> ASTNode:
        left = self.multiplicative()
        while self.match(TokenType.PLUS, TokenType.MINUS):
            op_tok = self.current_token()
            self.pos += 1
            right = self.multiplicative()
            op = "+" if op_tok.type == TokenType.PLUS else "-"
            left = BinaryOpNode(left=left, op=op, right=right, line=op_tok.line, col=op_tok.col)
        return left

    def multiplicative(self) -> ASTNode:
        left = self.unary()
        while self.match(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op_tok = self.current_token()
            self.pos += 1
            right = self.unary()
            op_map = {TokenType.STAR: "*", TokenType.SLASH: "/", TokenType.PERCENT: "%"}
            left = BinaryOpNode(left=left, op=op_map[op_tok.type], right=right, line=op_tok.line, col=op_tok.col)
        return left

    def unary(self) -> ASTNode:
        if self.match(TokenType.MINUS, TokenType.PLUS):
            op_tok = self.current_token()
            self.pos += 1
            op = "-" if op_tok.type == TokenType.MINUS else "+"
            operand = self.unary()
            return UnaryOpNode(op=op, operand=operand, line=op_tok.line, col=op_tok.col)
        return self.primary()

    def primary(self) -> ASTNode:
        atom = self.atom()
        # Handle function calls: atom(args)
        while self.match(TokenType.LPAREN):
            lparen = self.consume(TokenType.LPAREN)
            if not isinstance(atom, VarNode):
                raise ParserError("Only identifiers can be called as functions", lparen)
            args = []
            if not self.match(TokenType.RPAREN):
                args.append(self.expression())
                while self.match(TokenType.COMMA):
                    self.consume(TokenType.COMMA)
                    args.append(self.expression())
            self.consume(TokenType.RPAREN, "Expected ')' after function arguments")
            atom = CallNode(callee=atom.name, args=args, line=atom.line, col=atom.col)
        return atom

    def atom(self) -> ASTNode:
        tok = self.current_token()

        if tok.type == TokenType.NUMBER:
            self.pos += 1
            return LiteralNode(value=tok.value, raw_type="int" if isinstance(tok.value, int) else "float", line=tok.line, col=tok.col)
        elif tok.type == TokenType.STRING:
            self.pos += 1
            return LiteralNode(value=tok.value, raw_type="str", line=tok.line, col=tok.col)
        elif tok.type == TokenType.TRUE:
            self.pos += 1
            return LiteralNode(value=True, raw_type="bool", line=tok.line, col=tok.col)
        elif tok.type == TokenType.FALSE:
            self.pos += 1
            return LiteralNode(value=False, raw_type="bool", line=tok.line, col=tok.col)
        elif tok.type == TokenType.NONE:
            self.pos += 1
            return LiteralNode(value=None, raw_type="NoneType", line=tok.line, col=tok.col)
        elif tok.type == TokenType.IDENTIFIER:
            self.pos += 1
            return VarNode(name=tok.value, line=tok.line, col=tok.col)
        elif tok.type == TokenType.LPAREN:
            self.consume(TokenType.LPAREN)
            expr = self.expression()
            self.consume(TokenType.RPAREN, "Expected ')' after expression")
            return expr

        raise ParserError(f"Unexpected token in expression: {tok.type.name} ({repr(tok.value)})", tok)
