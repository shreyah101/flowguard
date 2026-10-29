# FlowGuard Review 2 - live demonstration (5-7 minutes)

## Before the presentation

From the project folder in PowerShell:

```powershell
python -m pytest -q
python flowguard_cli.py --serve
```

Open http://127.0.0.1:8080. No network connection is needed. Select
`slide_example.fg`. If port 8080 is busy, use `--serve --port 8081`.
Have a second PowerShell ready with the CLI backup below.

## 0:00-0:40 - Explain the problem and scope

"FlowGuard tracks untrusted input through a small Python-like language. We built
our own compiler frontend and use forward may-taint analysis on CFGs. We never
execute the submitted program. A finding is a potential unsafe flow, not a
confirmed exploit."

Show the editor's original Review 1 scenario. `input()` is at line 1,
`execute_query(query)` at line 8. Click Analyze.

## 0:40-1:10 - Overview

Expect one SQL risk, 31 tokens (including layout and EOF), 12 AST nodes,
6 CFG blocks and 6 worklist visits. These values are computed from this source;
editing whitespace may change token locations and editing statements changes counts.
The stage strip shows real completed stages. Explain that a failure leaves later
stages pending.

## 1:10-1:45 - Tokens, then AST

Open Tokens. Point to IDENTIFIER, IF, INDENT/DEDENT and line/column positions.
Open AST. Expand the If node, condition, then_body and else_body.
"Recursive descent consumes our tokens and builds this tree. Operator precedence
is implemented by distinct expression rules; we do not call ast.parse."

## 1:45-2:30 - Control Flow

Open Control Flow and click Fit. Point to Entry, condition, True/False branches,
join and Exit. "The syntax tree shows nesting; this graph makes possible control
transfers explicit. Both paths join, so a possible tainted value survives."
The two assignments to query have different abstract values; a may-analysis
keeps risk present on either predecessor.

## 2:30-3:20 - Taint Trace

Open Taint Trace, select the finding. Expect:

```text
input() L1 -> name L1 -> query L4 -> execute_query() L8
```

Click the query hop to select its editor line. Explain that the source fact and
hops were carried during transfer/join. The qualified CFG walk follows the True
branch. It is a static witness; predicate correlations are not solved.

## 3:20-3:50 - Report

Open Report, show the source/sink evidence, and export JSON or Markdown.
"We use teaching priorities based on modeled sink categories, not measured
exploit severity. Zero findings only means no modeled unsafe flow was found."

## 3:50-4:30 - Sanitizer comparison

Choose `sanitized_safe.fg`, Analyze, then Overview: zero modeled flows.
Choose `mismatched_sanitizer.fg`, Analyze: one command risk remains.
"Legacy sanitize is modeled as SQL-only. A SQL sanitizer cannot clear command risk."

## 4:30-5:10 - Loop and fixpoint

Choose `loop_accumulation.fg`, Analyze. Overview shows 9 worklist visits and
5 CFG blocks; expand the IN/OUT worklist. Open Control Flow to show LoopBack.
"Changed outputs reschedule successors. The finite source/category fact sets
stabilize, so the queue empties. Repeated witness hops do not affect equality."
The file-write finding concerns the content argument under our educational policy;
the literal filename itself is not tainted.

## 5:10-5:50 - Functions

Choose `interprocedural_call.fg`, Analyze. Taint Trace shows input, actual-to-formal
parameter mapping, cmd assignment, return and caller sink. In Control Flow select
`create_command` to show its actual CFG. "Each nonrecursive call solves a function
CFG with the caller's abstract argument states. We support branches and loops in
functions. Recursive summaries remain final-review work; recursion fails explicitly."

## 5:50-6:30 - Diagnostics and close

Choose `semantic_error.fg`, Analyze: variable initialized on only one branch is
reported; there is no clean result. Select `syntax_error.fg` to show the missing
colon and real failed stage. Return to slide_example, Analyze, then Overview.
Mention the verified test result and remaining scope limitations.

## Faculty questions and simple answers

- **Why a CFG as well as an AST?** The AST encodes grammar; the CFG encodes branch,
  merge, loop and return edges for data-flow propagation.
- **What is a fixpoint?** No block output changes, so no successors need rescheduling.
- **What is the lattice?** Each variable holds a finite subset of source/category
  facts, ordered by inclusion; the join is union.
- **Does strong update break monotonicity?** No. Assignment replaces a target, but
  its RHS transfer remains monotone with respect to the incoming fact sets.
- **Why keep taint if one branch assigns a constant?** May-analysis conservatively
  preserves risk from the other branch. It is a possibility, not a certain execution.
- **How are multiple sources handled?** Separate source facts survive expressions
  and joins; findings retain their own representative provenance.
- **How do loops terminate?** Finite facts and monotone transfers reach a fixpoint.
  Witness metadata is excluded from equality; a resource limit fails explicitly.
- **How are functions handled?** Actual facts bind to parameters, the callee CFG is
  solved, and reachable return facts propagate back. Internal sinks are checked.
- **Does it handle recursion?** It detects recursive call cycles and reports
  incomplete analysis. A conservative recursive-summary solver is future work.
- **Is sanitized input guaranteed safe?** No. These are documented educational
  sanitizer assumptions by category, not implementations or production guarantees.
- **What does no findings mean?** No unsafe source-to-sink flows under this model.
- **What remains unsupported?** Full Python, globals in functions, heap/alias and
  implicit flows, recursive summaries and path-sensitive branch feasibility.

## Backup CLI demonstration

```powershell
python flowguard_cli.py examples/slide_example.fg --tokens --ast --cfg --worklist
python flowguard_cli.py examples/sanitized_safe.fg
python flowguard_cli.py examples/command_injection.fg --json
python run_demo.py
```

For a shorter fallback use just `python flowguard_cli.py examples/slide_example.fg`.
If Python is unavailable on the presentation computer, install Python beforehand;
there is no cloud backend or bundled executable to fall back to.
