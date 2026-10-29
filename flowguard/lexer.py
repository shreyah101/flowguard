"""
FlowGuard: Lexical Analyzer (Module 1 - Lexical Analysis)
Converts raw source code into a stream of categorized tokens.
Handles keywords, identifiers, literals, operators, delimiters, and Python-style indentation.
"""

from enum import Enum, auto
from typing import List, Optional, Any, Dict


class TokenType(Enum):
    # Keywords
    DEF = auto()
    RETURN = auto()
    IF = auto()
    ELIF = auto()
    ELSE = auto()
    WHILE = auto()
    TRUE = auto()
    FALSE = auto()
    NONE = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    PASS = auto()

    # Identifiers & Literals
    IDENTIFIER = auto()
    NUMBER = auto()
    STRING = auto()

    # Operators
    EQUALS = auto()        # =
    PLUS = auto()          # +
    MINUS = auto()         # -
    STAR = auto()          # *
    SLASH = auto()         # /
    PERCENT = auto()       # %
    EQEQ = auto()          # ==
    NOTEQ = auto()         # !=
    LT = auto()            # <
    LTE = auto()           # <=
    GT = auto()            # >
    GTE = auto()           # >=

    # Delimiters
    LPAREN = auto()        # (
    RPAREN = auto()        # )
    COLON = auto()         # :
    COMMA = auto()         # ,

    # Layout
    NEWLINE = auto()
    INDENT = auto()
    DEDENT = auto()
    EOF = auto()


KEYWORDS = {
    "def": TokenType.DEF,
    "return": TokenType.RETURN,
    "if": TokenType.IF,
    "elif": TokenType.ELIF,
    "else": TokenType.ELSE,
    "while": TokenType.WHILE,
    "True": TokenType.TRUE,
    "False": TokenType.FALSE,
    "None": TokenType.NONE,
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "pass": TokenType.PASS,
}


class Token:
    def __init__(self, type_: TokenType, value: Any, line: int, col: int) -> None:
        self.type = type_
        self.value = value
        self.line = line
        self.col = col

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {repr(self.value)}, L{self.line}:C{self.col})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.name,
            "value": str(self.value) if self.value is not None else "",
            "line": self.line,
            "col": self.col
        }


class LexerError(Exception):
    def __init__(self, message: str, line: int, col: int) -> None:
        super().__init__(f"LexerError [Line {line}, Col {col}]: {message}")
        self.line = line
        self.col = col


class Lexer:
    """Hand-crafted Lexer with indentation sensitivity for Python-like syntax."""
    def __init__(self, source_code: str) -> None:
        self.source = source_code.replace("\r\n", "\n").replace("\r", "\n")
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: List[Token] = []
        self.indent_stack: List[int] = [0]
        self.at_line_start = True

    def peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        if idx < len(self.source):
            return self.source[idx]
        return None

    def advance(self) -> Optional[str]:
        if self.pos < len(self.source):
            ch = self.source[self.pos]
            self.pos += 1
            if ch == '\n':
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            return ch
        return None

    def tokenize(self) -> List[Token]:
        while self.pos < len(self.source):
            # Check indentation at start of line
            if self.at_line_start:
                self._handle_indentation()
                if self.pos >= len(self.source):
                    break

            ch = self.peek()

            # Handle whitespace within line
            if ch in (' ', '\t', '\r'):
                self.advance()
                continue

            # Handle comments (# to end of line)
            if ch == '#':
                while self.peek() is not None and self.peek() != '\n':
                    self.advance()
                continue

            # Handle Newline
            if ch == '\n':
                start_line = self.line
                start_col = self.col
                self.advance()
                # Don't emit consecutive newlines or leading empty lines
                if self.tokens and self.tokens[-1].type not in (TokenType.NEWLINE, TokenType.INDENT):
                    self.tokens.append(Token(TokenType.NEWLINE, "\\n", start_line, start_col))
                self.at_line_start = True
                continue

            # Two-character operators
            if ch == '=' and self.peek(1) == '=':
                start_col = self.col
                self.advance()
                self.advance()
                self.tokens.append(Token(TokenType.EQEQ, "==", self.line, start_col))
                continue
            if ch == '!' and self.peek(1) == '=':
                start_col = self.col
                self.advance()
                self.advance()
                self.tokens.append(Token(TokenType.NOTEQ, "!=", self.line, start_col))
                continue
            if ch == '<' and self.peek(1) == '=':
                start_col = self.col
                self.advance()
                self.advance()
                self.tokens.append(Token(TokenType.LTE, "<=", self.line, start_col))
                continue
            if ch == '>' and self.peek(1) == '=':
                start_col = self.col
                self.advance()
                self.advance()
                self.tokens.append(Token(TokenType.GTE, ">=", self.line, start_col))
                continue

            # Single-character tokens
            if ch == '=':
                self.tokens.append(Token(TokenType.EQUALS, "=", self.line, self.col))
                self.advance()
                continue
            if ch == '+':
                self.tokens.append(Token(TokenType.PLUS, "+", self.line, self.col))
                self.advance()
                continue
            if ch == '-':
                self.tokens.append(Token(TokenType.MINUS, "-", self.line, self.col))
                self.advance()
                continue
            if ch == '*':
                self.tokens.append(Token(TokenType.STAR, "*", self.line, self.col))
                self.advance()
                continue
            if ch == '/':
                self.tokens.append(Token(TokenType.SLASH, "/", self.line, self.col))
                self.advance()
                continue
            if ch == '%':
                self.tokens.append(Token(TokenType.PERCENT, "%", self.line, self.col))
                self.advance()
                continue
            if ch == '<':
                self.tokens.append(Token(TokenType.LT, "<", self.line, self.col))
                self.advance()
                continue
            if ch == '>':
                self.tokens.append(Token(TokenType.GT, ">", self.line, self.col))
                self.advance()
                continue
            if ch == '(':
                self.tokens.append(Token(TokenType.LPAREN, "(", self.line, self.col))
                self.advance()
                continue
            if ch == ')':
                self.tokens.append(Token(TokenType.RPAREN, ")", self.line, self.col))
                self.advance()
                continue
            if ch == ':':
                self.tokens.append(Token(TokenType.COLON, ":", self.line, self.col))
                self.advance()
                continue
            if ch == ',':
                self.tokens.append(Token(TokenType.COMMA, ",", self.line, self.col))
                self.advance()
                continue

            # String Literals
            if ch in ('"', "'"):
                self._tokenize_string(ch)
                continue

            # Number Literals
            if ch.isdigit():
                self._tokenize_number()
                continue

            # Identifiers & Keywords
            if ch.isalpha() or ch == '_':
                self._tokenize_identifier()
                continue

            raise LexerError(f"Unexpected character: {repr(ch)}", self.line, self.col)

        # Emit trailing newline if last token wasn't one
        if self.tokens and self.tokens[-1].type not in (TokenType.NEWLINE, TokenType.DEDENT):
            self.tokens.append(Token(TokenType.NEWLINE, "\\n", self.line, self.col))

        # Close all open indentation blocks
        while len(self.indent_stack) > 1:
            self.indent_stack.pop()
            self.tokens.append(Token(TokenType.DEDENT, "", self.line, self.col))

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.col))
        return self.tokens

    def _handle_indentation(self) -> None:
        """Measures leading indentation and pushes INDENT/DEDENT tokens."""
        indent_count = 0
        whitespace = set()
        while self.pos < len(self.source):
            ch = self.peek()
            if ch == ' ':
                whitespace.add(ch)
                indent_count += 1
                self.advance()
            elif ch == '\t':
                whitespace.add(ch)
                indent_count += 4
                self.advance()
            elif ch == '\r':
                self.advance()
            else:
                break

        # If empty line or comment-only line, ignore indentation changes
        if self.peek() in ('\n', '#', None):
            return

        if len(whitespace) > 1:
            raise LexerError("Mixed tabs and spaces in indentation", self.line, self.col)
        self.at_line_start = False
        current_indent = self.indent_stack[-1]

        if indent_count > current_indent:
            self.indent_stack.append(indent_count)
            self.tokens.append(Token(TokenType.INDENT, indent_count, self.line, self.col))
        elif indent_count < current_indent:
            while len(self.indent_stack) > 1 and indent_count < self.indent_stack[-1]:
                self.indent_stack.pop()
                self.tokens.append(Token(TokenType.DEDENT, "", self.line, self.col))
            if self.indent_stack[-1] != indent_count:
                raise LexerError(f"Inconsistent indentation level ({indent_count})", self.line, self.col)

    def _tokenize_string(self, quote_char: str) -> None:
        start_line = self.line
        start_col = self.col
        self.advance()  # consume opening quote
        chars = []

        while self.pos < len(self.source):
            ch = self.peek()
            if ch == quote_char:
                self.advance()  # consume closing quote
                self.tokens.append(Token(TokenType.STRING, "".join(chars), start_line, start_col))
                return
            elif ch == '\\':
                self.advance()
                esc = self.advance()
                if esc == 'n':
                    chars.append('\n')
                elif esc == 't':
                    chars.append('\t')
                elif esc == '\\':
                    chars.append('\\')
                elif esc in ('"', "'"):
                    chars.append(esc)
                else:
                    raise LexerError("Unsupported string escape", self.line, self.col)
            elif ch == '\n':
                raise LexerError("Unterminated string literal across newline", start_line, start_col)
            else:
                chars.append(self.advance())

        raise LexerError("Unterminated string literal at EOF", start_line, start_col)

    def _tokenize_number(self) -> None:
        start_line = self.line
        start_col = self.col
        num_str = ""
        is_float = False

        while self.peek() is not None and (self.peek().isdigit() or (self.peek() == '.' and not is_float)):
            if self.peek() == '.':
                is_float = True
            num_str += self.advance()

        val = float(num_str) if is_float else int(num_str)
        self.tokens.append(Token(TokenType.NUMBER, val, start_line, start_col))

    def _tokenize_identifier(self) -> None:
        start_line = self.line
        start_col = self.col
        ident = ""

        while self.peek() is not None and (self.peek().isalnum() or self.peek() == '_'):
            ident += self.advance()

        if ident in KEYWORDS:
            self.tokens.append(Token(KEYWORDS[ident], ident, start_line, start_col))
        else:
            self.tokens.append(Token(TokenType.IDENTIFIER, ident, start_line, start_col))
