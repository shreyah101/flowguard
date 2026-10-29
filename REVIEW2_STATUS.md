# FlowGuard Review 2 - factual implementation status

Verified 29 October 2026, on Windows with Python 3.13. The project remains in the
original workspace and uses the standard library at runtime. No deployment or
external infrastructure was introduced.

## Existing project audit

- Existing custom lexer, typed AST classes, recursive-descent expression parser,
  basic-block CFG builder, terminal/JSON/Markdown reports, CLI and demo runner
  were real implementations worth preserving.
- The original 9 tests passed. They covered a small set of basic constructs and
  did not establish the broader behavior promised in the Review 2 prompt.
- Parser `elif` handling consumed IF incorrectly. AST JSON omitted columns.
- Semantic analysis let branch-only/loop-only assignments appear definite, lacked
  arity and return-context errors, and allowed unresolved calls as INFO.
- The engine retained only one source per value, cleared every category for any
  sanitizer, visited disconnected blocks, and handled functions as shallow body
  scans. Standalone user calls and nested function control flow were incomplete.
- Zero-finding reports claimed SAFE/VERIFIED SAFE; the demo claimed tests had run.
- The web UI used external fonts/Mermaid, interpolated unescaped finding content,
  lacked exports and stale-response handling, and displayed AST as raw JSON.
- API request parsing and size checks needed hardening. It originally bound to all
  interfaces; it now binds only to loopback.

## Completed features

- Custom located lexer with indentation, strings/numbers, keywords/operators and
  lexical diagnostics; custom precedence parser with repaired elif support.
- Located AST serialization and expandable browser tree.
- Separate compiler diagnostics and security findings; stage-aware failures.
- Definite-assignment joins, known function arities, duplicate/conflicting
  definitions, duplicate parameters, return misuse and simple type warnings.
- Main/function CFGs with labeled branches, joins, loops/back edges, return exits
  and reachability pruning, including literal-condition pruning.
- Finite source/category fact sets, pointwise union, strong assignment updates,
  context-specific sanitizers and actual entry-driven fixpoint worklists.
- Nonrecursive call-context function CFG solves, including nested calls, branch
  returns, loops, internal sources/sinks and safe constant/sanitized returns.
- Maintained provenance with assignment, expression, parameter, return and sink
  hops; qualified compact CFG walks and actual source excerpts.
- Structured stage status, deterministic finding IDs, counters and evidence.
- Bounded inputs/visits/nesting; unsupported or limited analyses fail explicitly.
- Validated HTTP API, health/examples endpoints and static-asset allowlist.
- Offline editor with line numbers, syntax overlay, Tab insertion, Ctrl+Enter,
  diagnostics, six functional result tabs, graph routine selection/zoom/fit,
  selected taint traces and JSON/Markdown exports.
- Edit-staleness indication, disabled stale exports and revision/request guards.
- Nine examples with explicit expected outcomes; preserved original five examples.
- CLI functionality and demo script; README, project report and Review 2 script.

## Partial or unsupported features

| Area | Current boundary |
| --- | --- |
| Interprocedural analysis | Nonrecursive parameter/local scope; no reusable summary cache |
| Recursion | Cycles detected and reported as incomplete; no recursive-summary fixpoint |
| Path sensitivity | Literal conditions pruned; correlations between general predicates not solved |
| Provenance | Representative abstract witness; loop hops compacted and CFG walk capped at 256 |
| Types | Basic definite types and Unknown; no full type checker |
| Function scopes | Global reads, closures, nested definitions and nonlocal effects unsupported |
| Language | Small documented subset; no full Python, heap, alias, container or implicit-flow analysis |
| CFG rendering | Deterministic SVG, suitable for review-sized examples; not an industrial graph layout |
| Editor | Lightweight textarea/overlay; no autocomplete or breakpoint debugger |

## Verified tests and commands

- Baseline `python -m pytest -q`: **9 passed**, with a Windows cache warning.
- Final `python -m pytest -q`: **89 passed**, no skipped tests.
- `python flowguard_cli.py --all-examples`: all nine outcomes match the manifest.
  Seven examples complete; semantic_error and syntax_error intentionally fail.
- `python run_demo.py`: completes the primary pipeline and original five examples.
- CLI text and JSON runs completed; exported JSON parses and includes expected
  source/sink locations. Invalid single-file programs return exit code 2.
- `python -m compileall -q flowguard flowguard_cli.py run_demo.py`: succeeds.
- Bundled Node `--check flowguard/web/app.js`: succeeds.
- HTTP integration tests start an actual ephemeral localhost server and check
  health, examples, successful/failed analysis, malformed/oversized requests,
  static resources and disallowed paths.
- Server startup through `python -m flowguard.server 8080` and local browser access
  verified. Preview server stopped after final verification; restart with the
  documented `python flowguard_cli.py --serve` command.

## Actual browser verification

Performed through the in-app browser against the running local Python API:

- Primary slide: 31 tokens, 12 AST nodes, 6 CFG blocks, 6 visits, one SQL finding,
  source line 1 and sink line 8. All six stages complete.
- Token table and located AST expansion display backend results.
- CFG renders actual nodes/edges; function CFG selector and Fit work.
- Loop graph shows True/False and LoopBack; analysis reaches fixpoint after
  9 visits for 5 blocks in loop_accumulation.fg.
- Source-to-sink trace shows actual assignment hops and qualified branch walk.
- Sanitized SQL example reports zero modeled flows; command example reports one.
- Interprocedural example reports a command flow and exposes create_command CFG.
- Custom two-sink program yields two selectable findings; selection updates trace.
- Syntax error marks PARSE failed and later stages pending. Branch-dependent
  undefined variable marks SEMANTIC failed and displays its line/column.
- Editing sets results stale and disables export. Ctrl+Enter reanalyzes.
- Tab inserts four spaces; Reset restores the selected example.
- JSON and Markdown controls generated actual files in Downloads. Downloaded JSON
  was reopened and checked for completed status, one finding, source 1 / sink 8.
- Desktop 1280px layout measured side by side; 390px layout measured stacked with
  no page overflow. Temporary viewport overrides were reset after checking.
- Screenshot: output/review2-workbench.png.

Browser checks were interactive automation checks, not a committed browser test
suite. Delayed-response race guards were reviewed, but artificial network races
and exhaustive keyboard/screen-reader testing were not performed.

## Known issues and limitations

The may-analysis can report infeasible correlated flows. Sanitizers are modeled
assumptions. Both path and content are sensitive under the educational write_file
policy, so content-only risk is not proof of path traversal. No findings never
means universal security. Large graphs may require scrolling; node previews show
the first six statements with complete structured data available in JSON.
An inaccessible temporary pytest cache folder was created by the original baseline
run; test discovery is now scoped to tests and caching disabled. It does not affect
running the application or the verified suite.

## Final-review roadmap

1. Conservative recursive function summaries with their own fixpoint and tests.
2. Cache summaries by abstract argument context and benchmark worst-case inputs.
3. Add a constant-propagation/path-feasibility pass and independent correctness cases.
4. Extend documented scopes/types only with matching semantic and data-flow tests.
5. Improve large-graph navigation and accessible source-line highlighting.
6. Commit repeatable browser regression coverage, including delayed network races.

The five-stage core demonstration is working. Review readiness does not imply
support for the unsupported language and analysis features listed above.
