import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flowguard.lexer import Lexer, TokenType


class TestLexer(unittest.TestCase):
    def test_basic_tokens(self):
        code = "name = input()"
        lexer = Lexer(code)
        tokens = lexer.tokenize()
        types = [t.type for t in tokens if t.type not in (TokenType.NEWLINE, TokenType.EOF)]
        self.assertEqual(types, [TokenType.IDENTIFIER, TokenType.EQUALS, TokenType.IDENTIFIER, TokenType.LPAREN, TokenType.RPAREN])

    def test_indentation_block(self):
        code = "if x:\n    y = 1\nelse:\n    y = 2"
        lexer = Lexer(code)
        tokens = lexer.tokenize()
        token_types = [t.type for t in tokens]
        self.assertIn(TokenType.INDENT, token_types)
        self.assertIn(TokenType.DEDENT, token_types)


if __name__ == "__main__":
    unittest.main()
