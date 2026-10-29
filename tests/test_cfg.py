import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flowguard.lexer import Lexer
from flowguard.parser import Parser
from flowguard.cfg import CFGBuilder


class TestCFG(unittest.TestCase):
    def test_branching_cfg(self):
        code = "name = input()\nif name:\n    query = name\nelse:\n    query = 'guest'\nexecute_query(query)"
        tokens = Lexer(code).tokenize()
        ast = Parser(tokens).parse()
        cfgs = CFGBuilder().build_program_cfgs(ast)
        main_cfg = cfgs["main"]

        self.assertIsNotNone(main_cfg.entry_block)
        self.assertIsNotNone(main_cfg.exit_block)
        # Should contain Entry, IfCond, Then, Else, Join, Exit
        self.assertGreaterEqual(len(main_cfg.blocks), 5)


if __name__ == "__main__":
    unittest.main()
