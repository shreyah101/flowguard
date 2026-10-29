import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flowguard.lexer import Lexer
from flowguard.parser import Parser
from flowguard.ast_nodes import ProgramNode, AssignNode, IfNode, WhileNode, CallNode


class TestParser(unittest.TestCase):
    def test_parse_assignment(self):
        code = "query = 'SELECT * FROM users'"
        lexer = Lexer(code)
        parser = Parser(lexer.tokenize())
        ast = parser.parse()
        self.assertIsInstance(ast, ProgramNode)
        self.assertEqual(len(ast.body), 1)
        self.assertIsInstance(ast.body[0], AssignNode)
        self.assertEqual(ast.body[0].target, "query")

    def test_parse_if_else(self):
        code = "if active:\n    status = 1\nelse:\n    status = 0"
        lexer = Lexer(code)
        parser = Parser(lexer.tokenize())
        ast = parser.parse()
        self.assertIsInstance(ast.body[0], IfNode)
        self.assertEqual(len(ast.body[0].then_body), 1)
        self.assertEqual(len(ast.body[0].else_body), 1)

    def test_parse_while(self):
        code = "while count > 0:\n    count = count - 1"
        lexer = Lexer(code)
        parser = Parser(lexer.tokenize())
        ast = parser.parse()
        self.assertIsInstance(ast.body[0], WhileNode)


if __name__ == "__main__":
    unittest.main()
