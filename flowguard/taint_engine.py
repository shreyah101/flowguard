"""
FlowGuard: Taint Analysis Engine (Module 5 - Code Optimization / Data Flow Analysis)
Implements an iterative Forward Data-Flow Analysis with Worklist Algorithm to Fixpoint.
Tracks untrusted user input from Sources through program variables/branches to Sinks.
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from copy import deepcopy
import hashlib
from flowguard.ast_nodes import (
    ASTNode, ProgramNode, FunctionDefNode, AssignNode,
    IfNode, WhileNode, ReturnNode, PassNode, ExprStmtNode,
    BinaryOpNode, UnaryOpNode, CallNode, VarNode, LiteralNode
)
from flowguard.cfg import BasicBlock, ControlFlowGraph, format_ast_statement, format_expr
from flowguard.semantic import KNOWN_SOURCES, KNOWN_SINKS, KNOWN_SANITIZERS


class TaintRecord:
    """Stores provenance information about a tainted variable."""
    def __init__(self, source_name: str, source_line: int, path: Optional[List[Dict[str, Any]]] = None) -> None:
        self.source_name = source_name
        self.source_line = source_line
        # Path is a list of steps: [{"step": 1, "var": "x", "line": 1, "desc": "Assigned from input()"}]
        self.path: List[Dict[str, Any]] = path or []
        self.cfg_path: List[str] = []

    def clone(self) -> 'TaintRecord':
        record = TaintRecord(self.source_name, self.source_line, deepcopy(self.path))
        record.cfg_path = list(getattr(self, "cfg_path", []))
        return record

    def add_hop(self, var_name: str, line: int, action: str) -> None:
        if any(p["variable"] == var_name and p["line"] == line and p["action"] == action for p in self.path):
            return
        self.path.append({
            "step": len(self.path) + 1,
            "variable": var_name,
            "line": line,
            "action": action
        })

    def get_path_string(self) -> str:
        parts = []
        for p in self.path:
            parts.append(f"Line {p['line']} ({p['variable']})")
        return " -> ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_line": self.source_line,
            "path": self.path,
            "path_string": self.get_path_string()
        }


class Vulnerability:
    """Represents a discovered security flaw where untrusted data reaches a dangerous sink."""
    def __init__(
        self,
        vuln_type: str,
        severity: str,
        sink_name: str,
        sink_line: int,
        sink_code: str,
        tainted_arg: str,
        taint_record: TaintRecord,
        explanation: str
    ) -> None:
        self.vuln_type = vuln_type
        self.severity = severity
        self.sink_name = sink_name
        self.sink_line = sink_line
        self.sink_code = sink_code
        self.tainted_arg = tainted_arg
        self.taint_record = taint_record
        self.explanation = explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": hashlib.sha256(f"{self.sink_name}:{self.sink_line}:{self.tainted_arg}:{self.taint_record.source_name}:{self.taint_record.source_line}".encode()).hexdigest()[:12],
            "category": self.vuln_type,
            "cfg_path": getattr(self.taint_record, "cfg_path", []),
            "path_kind": "Representative static data-flow witness; other paths may exist. Branch correlations are not solved.",
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "sink_name": self.sink_name,
            "sink_line": self.sink_line,
            "sink_code": self.sink_code,
            "tainted_arg": self.tainted_arg,
            "source_name": self.taint_record.source_name,
            "source_line": self.taint_record.source_line,
            "path": self.taint_record.path,
            "path_string": self.taint_record.get_path_string(),
            "explanation": self.explanation
        }


class WorklistIterationLog:
    """Tracks one step of the worklist fixpoint process for demonstration / viva."""
    def __init__(self, step: int, block_id: str, in_taints: Dict[str, str], out_taints: Dict[str, str], changed: bool) -> None:
        self.step = step
        self.block_id = block_id
        self.in_taints = in_taints
        self.out_taints = out_taints
        self.changed = changed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "block_id": self.block_id,
            "in_vars": self.in_taints,
            "out_vars": self.out_taints,
            "changed": self.changed
        }


# A value is a finite map (source name, source line, risk category) -> witness.
FactKey = Tuple[str, int, str]
Value = Dict[FactKey, TaintRecord]
State = Dict[str, Value]


class AnalysisLimitError(ValueError):
    """Explicit failure: no clean result is returned on a resource/recursion limit."""


class TaintAnalysisEngine:
    """Forward may-analysis over a finite powerset of source/category facts.

    Witnesses are metadata, excluded from lattice equality. Direct assignment is
    a strong update. Each user call solves its function CFG with actual abstract
    arguments; recursive calls fail explicitly rather than invent a clean value.
    """
    def __init__(self, user_functions: Optional[Dict[str, FunctionDefNode]] = None) -> None:
        from flowguard.cfg import CFGBuilder
        self.user_functions = user_functions or {}
        builder = CFGBuilder()
        self.function_cfgs = {name: builder.build_cfg_for_stmts(fn.body, name)
                              for name, fn in self.user_functions.items()}
        self.vulnerabilities: List[Vulnerability] = []
        self.iteration_logs: List[WorklistIterationLog] = []
        self.steps = 0
        self.call_stack: List[str] = []
        self.current_block = ""
        self.collect = False

    @staticmethod
    def join(values: List[Value]) -> Value:
        result: Value = {}
        for value in values:
            for key, record in value.items():
                if key not in result:
                    result[key] = record.clone()
        return result

    @staticmethod
    def signature(state: State) -> Dict[str, frozenset]:
        return {var: frozenset(value) for var, value in state.items() if value}

    def analyze_cfg(self, cfg: ControlFlowGraph) -> Tuple[List[Vulnerability], List[WorklistIterationLog]]:
        self.vulnerabilities = []
        self.iteration_logs = []
        self.steps = 0
        self.solve(cfg, {}, True)
        unique = {}
        for finding in self.vulnerabilities:
            key = (finding.sink_line, finding.sink_name, finding.tainted_arg,
                   finding.taint_record.source_name, finding.taint_record.source_line)
            unique.setdefault(key, finding)
        self.vulnerabilities = list(unique.values())
        return self.vulnerabilities, self.iteration_logs

    def solve(self, cfg: ControlFlowGraph, initial: State, collect: bool) -> Value:
        from collections import deque
        saved_block, saved_collect = self.current_block, self.collect
        outputs: Dict[str, State] = {}
        inputs: Dict[str, State] = {}
        queue = deque([cfg.entry_block.id])
        scheduled = {cfg.entry_block.id}
        while queue:
            self.steps += 1
            if self.steps > 20000:
                raise AnalysisLimitError("Analysis exceeded 20000 block visits")
            bid = queue.popleft()
            scheduled.remove(bid)
            block = cfg.blocks[bid]
            incoming: State = {}
            states = [outputs[p.id] for p in block.predecessors if p.id in outputs]
            if block is cfg.entry_block:
                states.append(initial)
            for state in states:
                for var, value in state.items():
                    incoming[var] = self.join([incoming.get(var, {}), value])
            inputs[bid] = incoming
            self.current_block = f"{cfg.name}:{bid}"
            self.collect = False
            new, _ = self.transfer(block, incoming)
            changed = bid not in outputs or self.signature(outputs[bid]) != self.signature(new)
            outputs[bid] = new
            self.iteration_logs.append(WorklistIterationLog(
                len(self.iteration_logs) + 1, self.current_block,
                {k: str(len(v)) + " risk facts" for k, v in incoming.items() if v},
                {k: str(len(v)) + " risk facts" for k, v in new.items() if v}, changed))
            if changed:
                for successor in block.successors:
                    if successor.id not in scheduled:
                        scheduled.add(successor.id)
                        queue.append(successor.id)
        returns: List[Value] = []
        # Emit only from converged reachable states.
        for bid, incoming in inputs.items():
            self.current_block = f"{cfg.name}:{bid}"
            self.collect = collect
            _, returned = self.transfer(cfg.blocks[bid], incoming)
            returns.append(returned)
        self.current_block, self.collect = saved_block, saved_collect
        return self.join(returns)

    def hop(self, value: Value, variable: str, line: int, action: str) -> Value:
        result = self.join([value])
        for record in result.values():
            record.add_hop(variable, line, action)
            route = getattr(record, "cfg_path", [])
            if not route or route[-1] != self.current_block:
                # Bounded compact route; repeated loop visits are summarized.
                if len(route) < 256:
                    route.append(self.current_block)
            record.cfg_path = route
        return result

    def transfer(self, block: BasicBlock, incoming: State) -> Tuple[State, Value]:
        state = {var: self.join([value]) for var, value in incoming.items()}
        for value in state.values():
            for record in value.values():
                if len(record.cfg_path) < 256 and (not record.cfg_path or record.cfg_path[-1] != self.current_block):
                    record.cfg_path.append(self.current_block)
        returned: Value = {}
        for inst in block.instructions:
            if isinstance(inst, AssignNode):
                value = self.expression(inst.value, state)
                state[inst.target] = self.hop(value, inst.target, inst.line,
                    f"Assignment: {format_ast_statement(inst)}")
            elif isinstance(inst, ExprStmtNode):
                self.expression(inst.expr, state)
            elif isinstance(inst, ReturnNode):
                returned = self.hop(self.expression(inst.value, state), "return", inst.line,
                                    "Return value to caller")
                break
        return state, returned

    def expression(self, expr: Optional[ASTNode], state: State) -> Value:
        from flowguard.semantic import SANITIZER_CONTEXTS, SENSITIVE_ARGUMENTS
        if expr is None or isinstance(expr, LiteralNode):
            return {}
        if isinstance(expr, VarNode):
            return self.join([state.get(expr.name, {})])
        if isinstance(expr, UnaryOpNode):
            return self.expression(expr.operand, state)
        if isinstance(expr, BinaryOpNode):
            return self.hop(self.join([self.expression(expr.left, state), self.expression(expr.right, state)]),
                            format_expr(expr), expr.line, f"Expression: {format_expr(expr)}")
        if not isinstance(expr, CallNode):
            return {}
        args = [self.expression(arg, state) for arg in expr.args]
        name = expr.callee
        if name in KNOWN_SOURCES:
            record = TaintRecord(name + "()", expr.line)
            value = {(name + "()", expr.line, info["type"]): record.clone()
                     for info in KNOWN_SINKS.values()}
            return self.hop(value, name + "()", expr.line, "Source: untrusted input")
        if name in SANITIZER_CONTEXTS:
            value = self.join(args)
            value = {key: rec for key, rec in value.items() if key[2] not in SANITIZER_CONTEXTS[name]}
            return self.hop(value, name + "()", expr.line, "Sanitizer: clears only its modeled context")
        if name in KNOWN_SINKS:
            info = KNOWN_SINKS[name]
            for index in SENSITIVE_ARGUMENTS[name]:
                if index >= len(args):
                    continue
                for key, record in args[index].items():
                    if key[2] == info["type"] and self.collect:
                        rec = self.hop({key: record}, name + "()", expr.line, "Sink: sensitive argument")[key]
                        self.vulnerabilities.append(Vulnerability(info["type"], info["severity"], name,
                            expr.line, format_expr(expr), format_expr(expr.args[index]), rec,
                            f"Possible {info['type']} risk: {key[0]} at line {key[1]} reaches {name} at line {expr.line}. "
                            "This is a static possibility, not confirmed exploitation."))
            return {}
        if name in self.user_functions:
            if name in self.call_stack or len(self.call_stack) >= 12:
                raise AnalysisLimitError("Recursive or excessively deep calls are unsupported; analysis is incomplete")
            fn = self.user_functions[name]
            initial = {param: self.hop(value, f"{name}:{param}", expr.line,
                        f"Call {name}: argument to parameter {param}")
                       for param, value in zip(fn.params, args)}
            self.call_stack.append(name)
            try:
                returned = self.solve(self.function_cfgs[name], initial, self.collect)
            finally:
                self.call_stack.pop()
            return self.hop(returned, name + "()", expr.line, "Function return received by caller")
        return self.hop(self.join(args), name + "()", expr.line, "Conservative builtin result")
