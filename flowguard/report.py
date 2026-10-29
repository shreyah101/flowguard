"""
FlowGuard: Vulnerability Report Generator (Stage 5)
Formats detected security flaws with detailed provenance paths,
remediation guidance, and compiler analysis summaries.
Supports ANSI terminal styling, Markdown, and JSON.
"""

from typing import List, Dict, Any, Optional
from flowguard.taint_engine import Vulnerability, WorklistIterationLog
from flowguard.semantic import SemanticIssue


REMEDIATION_MAP = {
    "SQL Injection": (
        "Use parameterized prepared statements in the real application. "
        "Parameter binding is outside this toy language; modeled sanitizers are educational assumptions."
    ),
    "Command Injection": (
        "Avoid executing raw shell strings via system() or popen(). Use subprocess execution "
        "with argument lists and no shell=True, or rigorously whitelist allowed command arguments."
    ),
    "Code Injection": (
        "Never pass user-supplied input into eval() or exec(). Use safe parsers like json.loads() "
        "or ast.literal_eval() if parsing structured data."
    ),
    "Path Traversal / Arbitrary File Write": (
        "Sanitize file paths using os.path.basename() and verify that the canonical path resides "
        "within the intended directory root before writing."
    ),
    "Cross-Site Scripting (XSS)": (
        "Apply context-aware output encoding (e.g., html_escape()) before rendering user input "
        "into web responses or DOM trees."
    )
}


class ReportGenerator:
    """Generates user-friendly, explainable vulnerability reports."""

    @staticmethod
    def generate_terminal_report(
        vulnerabilities: List[Vulnerability],
        semantic_issues: Optional[List[SemanticIssue]] = None,
        source_code: Optional[str] = None
    ) -> str:
        code_lines = source_code.splitlines() if source_code else []
        output = []

        output.append("=" * 72)
        output.append("               FLOWGUARD SECURITY ANALYSIS REPORT")
        output.append("    Compiler-Based Taint Tracking & Data-Flow Security Engine")
        output.append("=" * 72)

        # Semantic issues if any
        if semantic_issues:
            output.append("\n[*] SEMANTIC ANALYSIS WARNINGS:")
            for issue in semantic_issues:
                output.append(f"    - [{issue.severity}] Line {issue.line}: {issue.message}")

        if not vulnerabilities:
            output.append("\n[COMPLETED] No modeled unsafe flows detected")
            output.append("    No unvalidated tainted data flows detected reaching sensitive sinks.")
            output.append("=" * 72)
            return "\n".join(output)

        output.append(f"\n[!] POTENTIAL UNSAFE FLOWS: {len(vulnerabilities)}\n")

        for idx, vuln in enumerate(vulnerabilities, 1):
            output.append("-" * 72)
            output.append(f"VULNERABILITY #{idx}: {vuln.vuln_type.upper()} [{vuln.severity} SEVERITY]")
            output.append("-" * 72)

            # Source Info
            output.append(f"  [1] TAINT SOURCE:")
            output.append(f"      Function  : {vuln.taint_record.source_name}")
            output.append(f"      Location  : Line {vuln.taint_record.source_line}")
            if code_lines and 0 < vuln.taint_record.source_line <= len(code_lines):
                src_code = code_lines[vuln.taint_record.source_line - 1].strip()
                output.append(f"      Code      : {src_code}")

            # Propagation Path
            output.append(f"\n  [2] DATA PROPAGATION PATH:")
            output.append(f"      Overview  : {vuln.taint_record.get_path_string()}")
            output.append(f"      Detailed Hops:")
            for hop in vuln.taint_record.path:
                output.append(f"        Step {hop['step']}: Line {hop['line']} -> {hop['action']}")

            # Sink Info
            output.append(f"\n  [3] SENSITIVE SINK:")
            output.append(f"      Sink Name : {vuln.sink_name}()")
            output.append(f"      Location  : Line {vuln.sink_line}")
            output.append(f"      Sink Call : {vuln.sink_code}")
            output.append(f"      Tainted Arg: {vuln.tainted_arg}")

            # Explanation & Why it is dangerous
            output.append(f"\n  [4] WHY THIS IS RISKY:")
            output.append(f"      Untrusted input entered at Line {vuln.taint_record.source_line} through {vuln.taint_record.source_name}.")
            output.append(f"      The data-flow engine tracked this value across control-flow branches and variable assignments")
            output.append(f"      until it was supplied directly into '{vuln.sink_name}()' without intermediate sanitization.")

            # Remediation
            remediation = REMEDIATION_MAP.get(vuln.vuln_type, "Sanitize the tainted variable before passing it to the sink.")
            output.append(f"\n  [5] RECOMMENDED REMEDIATION:")
            output.append(f"      {remediation}")
            output.append("")

        output.append("Static possibilities under the supported model; not confirmed exploitation.")
        output.append("=" * 72)
        return "\n".join(output)

    @staticmethod
    def generate_markdown_report(vulnerabilities: List[Vulnerability]) -> str:
        lines = []
        lines.append("# FlowGuard Security Analysis Report\n")
        lines.append("Static possibilities under an educational model; not confirmed exploits or a security guarantee.\n")
        lines.append("> Mini Compiler-Based Taint Tracking & Data-Flow Analysis Tool\n")

        if not vulnerabilities:
            lines.append("### Status: No modeled unsafe flows detected\nNo tainted data flows reached dangerous sinks.")
            return "\n".join(lines)

        lines.append(f"### Potential Unsafe Flows ({len(vulnerabilities)})\n")
        for i, v in enumerate(vulnerabilities, 1):
            lines.append(f"#### {i}. {v.vuln_type} (`{v.severity}`)\n")
            lines.append(f"- **Source**: `{v.taint_record.source_name}` at Line {v.taint_record.source_line}")
            lines.append(f"- **Sink**: `{v.sink_name}()` at Line {v.sink_line}")
            lines.append(f"- **Tainted Expression**: `{v.tainted_arg}`")
            lines.append(f"- **Propagation Path**:")
            lines.append(f"  `{v.taint_record.get_path_string()}`\n")
            lines.append("```")
            for hop in v.taint_record.path:
                lines.append(f"Step {hop['step']}: Line {hop['line']} -> {hop['action']}")
            lines.append("```\n")
            lines.append(f"> **Remediation**: {REMEDIATION_MAP.get(v.vuln_type, 'Sanitize input before calling sink.')}\n")

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(
        vulnerabilities: List[Vulnerability],
        semantic_issues: List[SemanticIssue],
        iteration_logs: List[WorklistIterationLog]
    ) -> Dict[str, Any]:
        return {
            "summary": {
                "vulnerabilities_count": len(vulnerabilities),
                "semantic_issues_count": len(semantic_issues),
                "status": "FAILED" if any(s.severity == "ERROR" for s in semantic_issues) else "FINDINGS_DETECTED" if vulnerabilities else "NO_MODELED_UNSAFE_FLOWS"
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "semantic_issues": [s.to_dict() for s in semantic_issues],
            "fixpoint_worklist_steps": [log.to_dict() for log in iteration_logs]
        }
