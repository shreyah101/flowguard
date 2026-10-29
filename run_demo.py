#!/usr/bin/env python3
"""
FlowGuard: Master Demonstration Script
Runs all benchmark examples, displays compiler pipeline artifacts,
and showcases the Data-Flow Fixpoint analysis.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flowguard.analyzer import FlowGuardAnalyzer
from flowguard_cli import pretty_print_ast, print_worklist_table


def main():
    print("=" * 80)
    print("           FLOWGUARD COMPILER-BASED SECURITY ANALYSIS TOOL")
    print("   Tracking Untrusted User Input from Source -> Program Flow -> Dangerous Sinks")
    print("=" * 80)
    print("Project Authors:")
    print("  - Shreya Sundli     (24BCE2546)")
    print("  - Pranakshay Agarwal (24BCE2163)")
    print("  - Shlok Shembhole   (24BAI0205)")
    print("Course: Compiler Design Project Review")
    print("=" * 80)

    analyzer = FlowGuardAnalyzer()

    # 1. Focus on the Slide 12 End-to-End Example
    slide_file = Path(BASE_DIR) / "examples" / "slide_example.fg"
    print(f"\n[+] PHASE 1: COMPILER PIPELINE STAGES ON SLIDE 12 EXAMPLE ({slide_file})\n")
    with open(slide_file, "r", encoding="utf-8") as f:
        code = f.read()

    print("Source Code Under Analysis:")
    print("-" * 40)
    for idx, line in enumerate(code.splitlines(), 1):
        print(f"  {idx:2d} | {line}")
    print("-" * 40)

    res = analyzer.analyze(code)

    print("\n--- STAGE 1: LEXICAL ANALYSIS (Tokens Created) ---")
    print(f"Total tokens generated: {len(res.tokens)}")
    print(f"Sample tokens: {res.tokens[:6]} ...")

    print("\n--- STAGE 2: SYNTAX ANALYSIS (Abstract Syntax Tree) ---")
    pretty_print_ast(res.ast)

    print("\n--- STAGE 3: CONTROL FLOW GRAPH (Basic Blocks & Branch Edges) ---")
    main_cfg = res.cfgs["main"]
    for bid, b in main_cfg.blocks.items():
        succ_info = ", ".join(f"{s.id} ({b.edge_labels.get(s.id, '')})" for s in b.successors) or "Exit"
        print(f"  Block {bid:<10} | {b.label:<14} | Successors: {succ_info}")

    print("\n--- STAGE 4: DATA-FLOW ANALYSIS & FIXPOINT CONVERGENCE ---")
    print_worklist_table(res.iteration_logs)

    print("\n--- STAGE 5: VULNERABILITY REPORT GENERATED ---")
    print(res.get_terminal_report())

    # 2. Run over all benchmark examples
    print("\n" + "=" * 80)
    print("[+] PHASE 2: BENCHMARK SUITE COVERAGE")
    print("=" * 80)
    examples = [
        "slide_example.fg",
        "command_injection.fg",
        "sanitized_safe.fg",
        "loop_accumulation.fg",
        "interprocedural_call.fg"
    ]
    for ex in examples:
        ex_path = Path(BASE_DIR) / "examples" / ex
        with open(ex_path, "r", encoding="utf-8") as f:
            c = f.read()
        r = analyzer.analyze(c)
        status = f"COMPLETED ({len(r.vulnerabilities)} potential flows)" if r.vulnerabilities else "COMPLETED (no modeled unsafe flows)"
        print(f"  * {ex:<26} -> {status}")
        for v in r.vulnerabilities:
            print(f"      - {v.vuln_type} [L{v.sink_line}] via: {v.taint_record.get_path_string()}")

    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE. Run python -m pytest -q for the test suite.")
    print("To launch the interactive Web Dashboard:")
    print("  python flowguard_cli.py --serve")
    print("  Then open: http://localhost:8080")
    print("=" * 80)


if __name__ == "__main__":
    main()
