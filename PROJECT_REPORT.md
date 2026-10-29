# FlowGuard: A Taint-Tracking Static Analyzer Using Data Flow Analysis
## Compiler Design - Review 2 implementation report

Authors: Shreya Sundli (24BCE2546), Pranakshay Agarwal (24BCE2163),
Shlok Shembhole (24BAI0205). Updated 29 October 2026.

## 1. Problem statement

Untrusted application input can flow through variables, expressions and functions
before it reaches sensitive operations. Text matching alone cannot explain these
flows or distinguish a killed assignment from a propagated value. FlowGuard uses
compiler representations and a forward data-flow framework to demonstrate this
problem on a documented Python-like subset.

## 2. Objectives

Build a custom frontend, represent control flow, compute taint to a fixpoint, and
explain possible unsafe source-to-sink flows. Preserve the five Review 1 stages:
lexer, parser, CFG builder, taint engine, report generator. Semantic validation
supports the pipeline. The project does not execute analyzed programs, auto-fix
security issues, support all Python, or replace professional analysis.

## 3. Proposed versus implemented architecture

The proposed five-stage pipeline is implemented as Python modules with shared
serializable results consumed by the CLI and a standard-library HTTP server.
The UI shows tokens, located AST nodes, real routine CFGs, worklist states,
source-to-sink provenance and reports. The original lexer, AST model, parser,
CFG builder and reporting interfaces were retained and extended. The original
single-record engine was replaced after audit found lost source/context facts,
shallow function handling, and analysis of unreachable blocks.

## 4. Lexer design (Module 1)

A hand-written scanner advances through the source with line/column tracking.
Identifiers use a keyword table. Numeric and quoted-string scanners produce
values; each token exposes type, value and location. An indentation stack emits
INDENT/DEDENT; unmatched dedents are errors. Blank/comment lines do not change
indentation. CRLF is normalized. Strings reject malformed/newline literals and
unsupported escapes. Tabs count as four spaces, with mixed indentation on a
code line rejected. No host Python lexer/compiler is used.

## 5. Parser and AST (Module 2)

Recursive descent consumes only lexer tokens, using lookahead for assignment.
Expression rules implement precedence and left associativity. `elif` lowers to
an If node in the else body. Suites can be indented or simple inline statements.
AST nodes cover program, definition, assignment, branch, loop, return, pass,
expression statement, binary/unary operation, call, variable and literal.
Every serialization carries line and column. The browser renders this object
as expandable native details elements, without fabricating nodes.

A compact grammar (details and exclusions are in README):

```text
program    := statement* EOF
statement  := definition | if | while | return | pass | assignment | expression
suite      := ':' (NEWLINE INDENT statement+ DEDENT | statement)
expression := or -> and -> not -> comparison -> additive -> multiplicative -> unary -> primary
primary    := literal | identifier | identifier '(' arguments? ')' | '(' expression ')'
```

Chained comparisons are explicitly rejected; users can write `a < b and b < c`.

## 6. Semantic analysis (Module 3)

The first pass collects top-level function signatures and rejects conflicting
names and duplicate parameters. A forward environment maps definitely assigned
variables to simple types or Unknown. Assignment validates its RHS before
updating the environment. If-branch joins intersect variables on continuing
paths; differing types become Unknown. Returning branches do not contribute to
continuing state. Loop-body-only assignments are not definitely initialized after
the loop, since it may execute zero times. Undefined variables/functions, arity
errors, nested definitions and return outside a function are errors. Obvious
operand-type mismatches are warnings, not invented dynamic type certainty.
Functions have parameters and locals; reading external globals is unsupported.
Errors stop CFG/data-flow analysis and remain separate from security findings.

## 7. Basic blocks and CFG construction (Module 5)

Straight-line statements share basic blocks. If nodes create a condition block,
True/False branches and join. While nodes create header/body/after blocks with
LoopBack edges. Returns connect directly to routine exit and stop sequential
construction. Each top-level function has a separate CFG. Literal conditions
prune impossible edges. A reachability traversal removes disconnected blocks;
nonliteral predicate correlations are not solved. Blocks expose stable IDs,
instructions, source lines, predecessors, successors and labeled edges.
JSON nodes/edges power deterministic SVG layout with longest-path ranks on the CFG minus loop back edges; loop/back edges
route outside the nodes. Mermaid and DOT text exports remain for compatibility.

## 8. Taint lattice and transfer functions

Let S be the finite set of source sites identified by function name and line,
and C the fixed set of modeled sink categories. Each variable has a subset of
S x C, ordered by inclusion. A fact has a representative provenance record.
The lattice state is the finite product over variables. Empty means no modeled
source risk for that variable; it does not mean universal runtime safety.

- Join: pointwise union of predecessor fact sets.
- Source: generate facts for every modeled category at that source site.
- Assignment: strong replacement of target facts by RHS facts.
- Literal: empty facts; reassigning a constant kills the old target value.
- Unary/binary: conservatively propagate operand facts by union.
- Sanitizer: subtract only its modeled categories.
- Sink: inspect policy-sensitive arguments and emit matching-category facts.

Distinct source facts survive joins and expressions. Legacy `sanitize` and
`escape_sql` clear SQL only; SQL sanitization cannot clear command risk.
The exact sources, sinks, arities, sensitive positions and sanitizer assumptions
are maintained in `semantic.py` and documented in README. Both arguments to
write_file are sensitive in the teaching model. This intentionally conservative
content policy should not be confused with proof of attacker-controlled paths.

## 9. Worklist, fixpoint and complexity

Initialize a queue with routine entry. On each visit, union reachable predecessor
outputs (and entry parameter facts), then transfer the block's instructions.
Schedule successors on first visit or changed abstract output. Stop on empty
queue. Collect findings from converged reachable block inputs. This prevents
unreachable statements and intermediate analysis states from being presented as
final evidence. Logs count actual block visits, including per-call function solves;
these are not a fabricated number of whole-program passes.

Transfer functions are monotone in the input lattice even though assignment is
a strong update: a larger input cannot produce fewer RHS source facts. Finite
lattice height therefore gives termination for nonrecursive calls, subject to
explicit resource limits. Provenance metadata is excluded from state equality,
so loop witness growth cannot prevent convergence.

For N source characters, lexing is O(N) apart from value conversion; parsing is
linear in tokens for this grammar, with stack proportional to nesting. CFG
construction/reachability is O(B + E + I) for blocks, edges and instructions.
Let V be variables, F the number of source/category facts, K actual block visits,
and P the maximum retained witness size. A conservative data-flow cost is
O(K (Emax V F + Imax F) P), plus recursively invoked call solves, where Emax is
maximum block indegree and Imax is maximum expression/statement work in a block.
State storage is O(B V F P); iteration logs add their serialized state summaries.
These are dependency bounds, not claims of constant-time analysis. Repeated
per-call solves can be expensive; there is no summary cache in this version.

## 10. Focused interprocedural approach

At each user call, actual argument abstract values bind to formal parameters.
The engine solves that function's CFG, including branches, loops, local strong
updates, internal sinks and reachable return expressions. Returned facts carry
parameter/call/return provenance back to the caller. Standalone calls are analyzed,
so an internal sink is not missed merely because the caller ignores the result.
Constants and sanitized returns do not fall back to propagating all input taint.

Nonrecursive nested calls are supported. A repeated name on the call stack or
more than 12 nested calls produces an explicit incomplete-analysis error.
Recursive summaries were not implemented; the tool does not silently truncate
recursion and declare no findings. Uncalled function bodies do not create
reachable findings. Only parameter/local scope is currently modeled.

## 11. Provenance and reports

Source facts carry real transfer-generated hops. Joins retain one representative
witness per fact, rather than mixing steps from independent sources. Repeated
loop hops are compacted; qualified CFG walks are capped at 256 entries. The UI
labels these as static data-flow witnesses, since path-sensitive constraints are
not solved. Reports include deterministic IDs, teaching priority, category,
source/sink locations, source excerpts, argument expression, hops, CFG walk and
explanation. Terminal, JSON and downloadable Markdown exports share the result.

Completed-with-findings, completed-without-modeled-flows, and failed analysis
are distinct. Zero findings never claim complete security. A failed stage leaves
later stages pending; no fake completion animation runs. PRIORITY is a teaching
rubric: code/shell CRITICAL, query/file HIGH, HTML MEDIUM; no CVSS claim is made.

## 12. Experimental evaluation

Baseline: `python -m pytest -q` completed with 9 passed and a Windows cache warning.
After implementation: `python -m pytest -q` completed with **85 passed**.
The expanded tests cover lexer errors/locations, parser precedence/elif/errors,
semantic failures, graph edges, literal unreachable paths, strong updates,
context sanitizers, multiple sources/sinks, loop revisits, user-call returns,
internal sinks, constant returns, explicit recursion failures and API requests.
All nine .fg examples have executable expected-result tests (seven complete,
two intentionally fail with diagnostics). The five original valid examples remain.
The slide case reports source line 1 and sink line 8 from actual source locations.

Actual browser verification and remaining verification limits are recorded in
REVIEW2_STATUS.md. Run_demo prints a demonstration, not a claim that tests ran.

## 13. Safety and limitations

No evaluation, execution or subprocess launch of submitted source occurs.
The server binds to 127.0.0.1, allowlists static files, validates request envelopes,
rejects oversized bodies, and hides unexpected internal traces. Analyze limits:
100,000 source characters, 10,000 tokens, AST depth 60, call depth 12,
20,000 block visits. The HTTP body cap is 120,000 bytes. Limits fail explicitly.

Path insensitivity can report infeasible correlated flows. Implicit flows through
conditions, heap/alias analysis, arbitrary Python, recursive summaries, external
library semantics and function-global scope are outside this release. The modeled
sanitizers are assumptions, not production implementations. Unknown functions
are diagnosed rather than silently assumed clean.

## 14. Remaining final-review work

Add a conservative recursive-summary fixpoint; improve summary caching and
performance benchmarks; add a separate constant-propagation/path-feasibility
pass; improve layout for very large graphs; consider richer scope/type modeling
and automated browser regression tests. Each extension needs new correctness
tests and explicit documentation of changes to the analysis model.
