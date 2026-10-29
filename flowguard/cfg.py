"""
FlowGuard: Control Flow Graph (CFG) Builder (Module 5 - Basic Blocks & CFG)
Constructs a Control Flow Graph of Basic Blocks from the AST.
Captures straight-line sequences, branches (if/else), and loops (while).
Supports Mermaid, DOT, and JSON exports for visualization.
"""

from typing import List, Dict, Optional, Set
from flowguard.ast_nodes import (
    ASTNode, ProgramNode, FunctionDefNode, AssignNode,
    IfNode, WhileNode, ReturnNode, PassNode, ExprStmtNode,
    BinaryOpNode, UnaryOpNode, CallNode, VarNode, LiteralNode
)


def format_ast_statement(node: ASTNode) -> str:
    """Helper to generate concise string representations of AST statements for block visualization."""
    if isinstance(node, AssignNode):
        return f"{node.target} = {format_expr(node.value)}"
    elif isinstance(node, ExprStmtNode):
        return format_expr(node.expr)
    elif isinstance(node, ReturnNode):
        return f"return {format_expr(node.value)}" if node.value else "return"
    elif isinstance(node, PassNode):
        return "pass"
    return str(node)


def format_expr(node: Optional[ASTNode]) -> str:
    if node is None:
        return ""
    if isinstance(node, LiteralNode):
        if isinstance(node.value, str):
            return f'"{node.value}"'
        return str(node.value)
    elif isinstance(node, VarNode):
        return node.name
    elif isinstance(node, BinaryOpNode):
        return f"{format_expr(node.left)} {node.op} {format_expr(node.right)}"
    elif isinstance(node, UnaryOpNode):
        return f"{node.op} {format_expr(node.operand)}"
    elif isinstance(node, CallNode):
        args_str = ", ".join(format_expr(a) for a in node.args)
        return f"{node.callee}({args_str})"
    return "expr"


class BasicBlock:
    """A maximal sequence of straight-line instructions with single entry and exit."""
    def __init__(self, block_id: str, label: str = "") -> None:
        self.id = block_id
        self.label = label or block_id
        self.instructions: List[ASTNode] = []
        self.predecessors: List['BasicBlock'] = []
        self.successors: List['BasicBlock'] = []
        self.edge_labels: Dict[str, str] = {}  # successor_id -> label ("True", "False", "Fallthrough", etc.)

    def add_instruction(self, stmt: ASTNode) -> None:
        self.instructions.append(stmt)

    def add_successor(self, target: 'BasicBlock', label: str = "Fallthrough") -> None:
        if target not in self.successors:
            self.successors.append(target)
            self.edge_labels[target.id] = label
        if self not in target.predecessors:
            target.predecessors.append(self)

    def is_empty(self) -> bool:
        return len(self.instructions) == 0

    def get_lines(self) -> List[int]:
        lines = []
        for inst in self.instructions:
            if hasattr(inst, "line") and inst.line:
                lines.append(inst.line)
        return lines

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.label,
            "lines": self.get_lines(),
            "instructions": [
                {
                    "repr": format_ast_statement(inst),
                    "line": getattr(inst, "line", 0),
                    "type": inst.__class__.__name__
                }
                for inst in self.instructions
            ],
            "predecessors": [p.id for p in self.predecessors],
            "successors": [s.id for s in self.successors],
            "edge_labels": self.edge_labels
        }

    def __repr__(self) -> str:
        return f"<BasicBlock {self.id}: {len(self.instructions)} insts>"


class ControlFlowGraph:
    """Represents the complete CFG for a routine or main program."""
    def __init__(self, name: str = "main") -> None:
        self.name = name
        self.blocks: Dict[str, BasicBlock] = {}
        self.entry_block: Optional[BasicBlock] = None
        self.exit_block: Optional[BasicBlock] = None

    def add_block(self, block: BasicBlock) -> None:
        self.blocks[block.id] = block

    def to_mermaid(self) -> str:
        """Generates Mermaid flowchart diagram string."""
        lines = ["flowchart TD"]
        for b_id, block in self.blocks.items():
            # Build node content
            inst_text = []
            for inst in block.instructions:
                line_no = getattr(inst, 'line', '')
                prefix = f"L{line_no}: " if line_no else ""
                inst_text.append(f"{prefix}{format_ast_statement(inst)}")

            content = f"<b>{block.label} ({b_id})</b>"
            if inst_text:
                joined = "<br/>".join(inst_text)
                content += f"<hr/>{joined}"

            # Escape quotes for mermaid
            safe_content = content.replace('"', "'")
            lines.append(f'    {b_id}["{safe_content}"]')

        for b_id, block in self.blocks.items():
            for succ in block.successors:
                label = block.edge_labels.get(succ.id, "")
                if label:
                    lines.append(f'    {b_id} -->|"{label}"| {succ.id}')
                else:
                    lines.append(f'    {b_id} --> {succ.id}')

        return "\n".join(lines)

    def to_dot(self) -> str:
        """Generates Graphviz DOT string."""
        lines = [f'digraph CFG_{self.name} {{', '    node [shape=box, fontname="Helvetica"];']
        for b_id, block in self.blocks.items():
            content = f"{block.label}\\n"
            for inst in block.instructions:
                lno = getattr(inst, "line", "")
                content += f"L{lno}: {format_ast_statement(inst)}\\n"
            content = content.replace('"', '\\"')
            lines.append(f'    {b_id} [label="{content}"];')

        for b_id, block in self.blocks.items():
            for succ in block.successors:
                label = block.edge_labels.get(succ.id, "")
                lbl_str = f' [label="{label}"]' if label else ""
                lines.append(f'    {b_id} -> {succ.id}{lbl_str};')
        lines.append('}')
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "nodes": [b.to_dict() for b in self.blocks.values()],
            "edges": [{"source": b.id, "target": t.id, "label": b.edge_labels[t.id]}
                      for b in self.blocks.values() for t in b.successors],
            "name": self.name,
            "entry": self.entry_block.id if self.entry_block else None,
            "exit": self.exit_block.id if self.exit_block else None,
            "blocks": {bid: b.to_dict() for bid, b in self.blocks.items()},
            "mermaid": self.to_mermaid()
        }


class CFGBuilder:
    """Constructs CFGs from AST statements."""
    def __init__(self) -> None:
        self.block_counter = 0

    def _new_block_id(self, prefix: str = "B") -> str:
        bid = f"{prefix}{self.block_counter}"
        self.block_counter += 1
        return bid

    def build_cfg_for_stmts(self, statements: List[ASTNode], name: str = "main") -> ControlFlowGraph:
        cfg = ControlFlowGraph(name=name)

        entry = BasicBlock(self._new_block_id("Entry"), label="Entry")
        cfg.add_block(entry)
        cfg.entry_block = entry

        exit_block = BasicBlock(self._new_block_id("Exit"), label="Exit")
        cfg.add_block(exit_block)
        cfg.exit_block = exit_block

        current_block = entry

        current_block = self._build_stmts(statements, current_block, exit_block, cfg)

        if current_block and not self._is_terminated(current_block):
            current_block.add_successor(exit_block, "Fallthrough")

        # Only reachable blocks participate in analysis and visualizations.
        reachable = set()
        pending = [entry]
        while pending:
            block = pending.pop()
            if block.id in reachable:
                continue
            reachable.add(block.id)
            pending.extend(block.successors)
        cfg.blocks = {k: b for k, b in cfg.blocks.items() if k in reachable or b is exit_block}
        for block in cfg.blocks.values():
            block.predecessors = [p for p in block.predecessors if p.id in reachable]
        return cfg

    def _is_terminated(self, block: BasicBlock) -> bool:
        if not block.instructions:
            return False
        last = block.instructions[-1]
        return isinstance(last, ReturnNode)

    def _build_stmts(self, stmts: List[ASTNode], current_block: BasicBlock, exit_block: BasicBlock, cfg: ControlFlowGraph) -> Optional[BasicBlock]:
        curr = current_block

        for stmt in stmts:
            if curr is None:
                # Dead code after return
                break

            if isinstance(stmt, IfNode):
                curr = self._build_if(stmt, curr, exit_block, cfg)
            elif isinstance(stmt, WhileNode):
                curr = self._build_while(stmt, curr, exit_block, cfg)
            elif isinstance(stmt, ReturnNode):
                curr.add_instruction(stmt)
                curr.add_successor(exit_block, "Return")
                curr = None  # Block terminates
            elif isinstance(stmt, FunctionDefNode):
                # Function definitions are handled separately in their own CFG
                pass
            else:
                curr.add_instruction(stmt)

        return curr

    def _build_if(self, if_node: IfNode, current_block: BasicBlock, exit_block: BasicBlock, cfg: ControlFlowGraph) -> BasicBlock:
        cond_block = BasicBlock(self._new_block_id("IfCond"), label="If_Condition")
        cond_block.add_instruction(ExprStmtNode(expr=if_node.condition, line=if_node.line, col=if_node.col))
        cfg.add_block(cond_block)

        current_block.add_successor(cond_block, "Fallthrough")

        then_entry = BasicBlock(self._new_block_id("Then"), label="Then_Branch")
        cfg.add_block(then_entry)
        if not isinstance(if_node.condition, LiteralNode) or bool(if_node.condition.value):
            cond_block.add_successor(then_entry, "True")

        then_exit = self._build_stmts(if_node.then_body, then_entry, exit_block, cfg)

        join_block = BasicBlock(self._new_block_id("Join"), label="If_Join")
        cfg.add_block(join_block)

        if if_node.else_body:
            else_entry = BasicBlock(self._new_block_id("Else"), label="Else_Branch")
            cfg.add_block(else_entry)
            if not isinstance(if_node.condition, LiteralNode) or not bool(if_node.condition.value):
                cond_block.add_successor(else_entry, "False")
            else_exit = self._build_stmts(if_node.else_body, else_entry, exit_block, cfg)
            if else_exit and not self._is_terminated(else_exit):
                else_exit.add_successor(join_block, "Fallthrough")
        else:
            if not isinstance(if_node.condition, LiteralNode) or not bool(if_node.condition.value):
                cond_block.add_successor(join_block, "False")

        if then_exit and not self._is_terminated(then_exit):
            then_exit.add_successor(join_block, "Fallthrough")

        return join_block

    def _build_while(self, while_node: WhileNode, current_block: BasicBlock, exit_block: BasicBlock, cfg: ControlFlowGraph) -> BasicBlock:
        header_block = BasicBlock(self._new_block_id("LoopHead"), label="Loop_Header")
        header_block.add_instruction(ExprStmtNode(expr=while_node.condition, line=while_node.line, col=while_node.col))
        cfg.add_block(header_block)

        current_block.add_successor(header_block, "EnterLoop")

        body_entry = BasicBlock(self._new_block_id("LoopBody"), label="Loop_Body")
        cfg.add_block(body_entry)
        if not isinstance(while_node.condition, LiteralNode) or bool(while_node.condition.value):
            header_block.add_successor(body_entry, "True")

        after_loop = BasicBlock(self._new_block_id("LoopExit"), label="Loop_Exit")
        cfg.add_block(after_loop)
        if not isinstance(while_node.condition, LiteralNode) or not bool(while_node.condition.value):
            header_block.add_successor(after_loop, "False")

        body_exit = self._build_stmts(while_node.body, body_entry, exit_block, cfg)
        if body_exit and not self._is_terminated(body_exit):
            body_exit.add_successor(header_block, "LoopBack")

        return after_loop

    def build_program_cfgs(self, program: ProgramNode) -> Dict[str, ControlFlowGraph]:
        """Builds main CFG and individual CFGs for each function definition."""
        cfgs = {}
        top_stmts = []

        for stmt in program.body:
            if isinstance(stmt, FunctionDefNode):
                fn_cfg = self.build_cfg_for_stmts(stmt.body, name=stmt.name)
                cfgs[stmt.name] = fn_cfg
            else:
                top_stmts.append(stmt)

        main_cfg = self.build_cfg_for_stmts(top_stmts, name="main")
        cfgs["main"] = main_cfg
        return cfgs
