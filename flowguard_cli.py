#!/usr/bin/env python3
"""
FlowGuard CLI: Command-Line Interface for the FlowGuard Compiler Security Analyzer
Supports lexing, AST dumping, CFG visualization, worklist fixpoint tracing, and vulnerability reporting.
"""

import sys
import os
import argparse
import json
from pathlib import Path

# Ensure flowguard package is importable
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from flowguard.analyzer import FlowGuardAnalyzer
from flowguard.report import ReportGenerator


def pretty_print_ast(node, indent=0):
    spaces = "  " * indent
    node_type = node.__class__.__name__
    line_info = f" (L{getattr(node, 'line', '?')})"
    print(f"{spaces}{node_type}{line_info}")

    if hasattr(node, "__dict__"):
        for k, v in node.__dict__.items():
            if k in ("line", "col"):
                continue
            if isinstance(v, list):
                print(f"{spaces}  {k}: [")
                for item in v:
                    if hasattr(item, "__class__") and hasattr(item, "line"):
                        pretty_print_ast(item, indent + 2)
                    else:
                        print(f"{spaces}    {repr(item)}")
                print(f"{spaces}  ]")
            elif hasattr(v, "__class__") and hasattr(v, "line"):
                print(f"{spaces}  {k}:")
                pretty_print_ast(v, indent + 2)
            else:
                print(f"{spaces}  {k}: {repr(v)}")


def print_worklist_table(logs):
    print("\n" + "=" * 80)
    print("         DATA-FLOW ANALYSIS FIXPOINT WORKLIST TRACE (MODULE 5)")
    print("=" * 80)
    print(f"{'Step':<6} | {'Block':<12} | {'State Changed?':<15} | {'IN Variables':<20} | {'OUT Variables':<20}")
    print("-" * 80)
    for log in logs:
        ch_str = "YES (Repush succs)" if log.changed else "NO (Fixpoint on B)"
        in_vars = ", ".join(log.in_taints.keys()) or "{empty}"
        out_vars = ", ".join(log.out_taints.keys()) or "{empty}"
        print(f"{log.step:<6} | {log.block_id:<12} | {ch_str:<15} | {in_vars:<20} | {out_vars:<20}")
    print("=" * 80)
    print(">> Fixpoint reached: Worklist is empty. No further taint updates possible.\n")


def run_all_examples(analyzer: FlowGuardAnalyzer):
    examples_dir = os.path.join(current_dir, "examples")
    if not os.path.exists(examples_dir):
        print(f"Examples directory not found at {examples_dir}")
        return

    example_files = [f for f in os.listdir(examples_dir) if f.endswith(".fg")]
    print("\n" + "=" * 80)
    print(f"   RUNNING FLOWGUARD ON ALL TEST EXAMPLES ({len(example_files)} Files)")
    print("=" * 80)

    for ex in sorted(example_files):
        path = os.path.join(examples_dir, ex)
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        print(f"\n>>> Analyzing: {ex}")
        res = analyzer.analyze(code)
        vuln_count = len(res.vulnerabilities)
        if res.status == "failed":
            print(res.get_terminal_report())
        elif vuln_count > 0:
            print(f"    [!] Detected {vuln_count} Vulnerability(ies):")
            for v in res.vulnerabilities:
                print(f"        * {v.vuln_type} at Line {v.sink_line} ({v.sink_name}) via path: {v.taint_record.get_path_string()}")
        else:
            print(f"    [COMPLETED] No tainted flows reach sensitive sinks.")


def main():
    parser = argparse.ArgumentParser(
        description="FlowGuard: A Mini Compiler-Based Taint-Tracking Static Analyzer"
    )
    parser.add_argument("file", nargs="?", help="Path to source file (.fg or .py) to analyze")
    parser.add_argument("--tokens", action="store_true", help="Dump lexical tokens")
    parser.add_argument("--ast", action="store_true", help="Display Abstract Syntax Tree (AST)")
    parser.add_argument("--cfg", action="store_true", help="Display Control Flow Graph basic blocks & Mermaid")
    parser.add_argument("--worklist", action="store_true", help="Show step-by-step fixpoint iteration log")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--all-examples", action="store_true", help="Run analyzer on all bundled example cases")
    parser.add_argument("--serve", action="store_true", help="Start the interactive FlowGuard Web GUI dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Web server port (default 8080)")

    args = parser.parse_args()

    if args.serve:
        from flowguard.server import start_server
        start_server(port=args.port)
        return

    analyzer = FlowGuardAnalyzer()

    if args.all_examples:
        run_all_examples(analyzer)
        return

    if not args.file:
        # Default to slide_example if no file passed
        default_file = os.path.join(current_dir, "examples", "slide_example.fg")
        if os.path.exists(default_file):
            if not args.json:
                print(f"[*] No file specified. Running default Slide 12 example: {default_file}")
            args.file = default_file
        else:
            parser.print_help()
            sys.exit(1)

    try:
        source_code = Path(args.file).read_text(encoding="utf-8")
    except OSError as error:
        parser.error(str(error))

    res = analyzer.analyze(source_code)

    if args.tokens:
        print("\n--- STAGE 1: LEXICAL ANALYSIS (TOKENS) ---")
        for t in res.tokens:
            print(f"  {t}")

    if args.ast:
        print("\n--- STAGE 2: SYNTAX ANALYSIS (ABSTRACT SYNTAX TREE) ---")
        pretty_print_ast(res.ast)

    if args.cfg:
        print("\n--- STAGE 3: CONTROL FLOW GRAPH (CFG) ---")
        for name, cfg in res.cfgs.items():
            print(f"\n[CFG for '{name}']")
            for bid, b in cfg.blocks.items():
                print(f"  Block {bid} ({b.label}):")
                for inst in b.instructions:
                    print(f"    - L{getattr(inst, 'line', '?')}: {getattr(inst, 'repr', inst)}")
                succs = [f"{s.id} ({b.edge_labels.get(s.id, '')})" for s in b.successors]
                print(f"    Successors: {', '.join(succs) or 'None'}")
            print("\nMermaid Diagram:")
            print(cfg.to_mermaid())

    if args.worklist and res.status == "completed":
        print_worklist_table(res.iteration_logs)

    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(res.get_terminal_report())
    if res.status == "failed":
        sys.exit(2)


if __name__ == "__main__":
    main()
