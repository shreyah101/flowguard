"""Regression tests assert semantics, graph structure, reports, and HTTP behavior."""
from pathlib import Path
import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from flowguard.analyzer import FlowGuardAnalyzer
from flowguard.lexer import Lexer, LexerError, TokenType
from flowguard.parser import Parser, ParserError
from flowguard.semantic import SemanticAnalyzer
from flowguard.cfg import CFGBuilder
from flowguard.server import FlowGuardHTTPRequestHandler


def analyze(code):
    return FlowGuardAnalyzer().analyze(code)


@pytest.mark.parametrize('code,expected', [
    ('execute_query(input())', 1),
    ('a = input()\nb = a\nc = "x" + b\nexecute_query(c)', 1),
    ('a = input()\na = "constant"\nexecute_query(a)', 0),
    ('a = input()\nexecute_query(sanitize_sql(a))', 0),
    ('a = input()\nrun_command(sanitize_sql(a))', 1),
    ('a = input()\nrun_command(sanitize_command(a))', 0),
    ('a = input()\nwrite_file(sanitize_command(a), "x")', 1),
    ('a = input()\nwrite_file(sanitize_path(a), "x")', 0),
    ('a = input()\nwrite_file("fixed", a)', 1),
    ('a = input()\nx = ""\nif a:\n    x = a\nexecute_query(x)', 1),
    ('a = input()\nif a:\n    x = sanitize_sql(a)\nelse:\n    x = ""\nexecute_query(x)', 0),
    ('a = input()\nx = ""\ni = 2\nwhile i:\n    x = x + a\n    i = i - 1\nexecute_query(x)', 1),
    ('a = input()\nb = input()\nexecute_query(a + b)', 2),
    ('a = input()\nexecute_query(a)\nrun_command(a)', 2),
    ('x = execute_query(input())', 1),
    ('if execute_query(input()):\n    pass', 1),
    ('def f(x):\n    y = "SELECT " + x\n    return y\na = input()\nexecute_query(f(a))', 1),
    ('def f(x):\n    execute_query(x)\nf(input())', 1),
    ('def f(x):\n    return "constant"\nexecute_query(f(input()))', 0),
    ('def f(x):\n    return sanitize_sql(x)\nexecute_query(f(input()))', 0),
    ('def f(x):\n    if x:\n        return x\n    else:\n        return ""\nexecute_query(f(input()))', 1),
    ('def f(x):\n    return ""\n    execute_query(x)\nf(input())', 0),
    ('def f(x):\n    if x:\n        return ""\n    else:\n        return ""\n    execute_query(input())\nf(input())', 0),
    ('def f():\n    return input()\nexecute_query(f())', 1),
    ('def f(x):\n    return x\ndef g(x):\n    return f(x)\nexecute_query(g(input()))', 1),
    ('a = input()\nif a:\n    x = sanitize_sql(a)\nelse:\n    x = sanitize_command(a)\nexecute_query(x)\nrun_command(x)', 2),
])
def test_dataflow(code, expected):
    result = analyze(code)
    assert result.status == 'completed', result.get_terminal_report()
    assert len(result.vulnerabilities) == expected
    assert result.to_dict()['statistics']['converged']
    for finding in result.to_dict()['findings']:
        assert finding['path'][0]['action'].startswith('Source')
        assert finding['path'][-1]['action'].startswith('Sink')
        assert finding['cfg_path']


@pytest.mark.parametrize('code,message', [
    ('execute_query(x)', 'before assignment'),
    ('flag = input()\nif flag:\n    x = 1\nprint(x)', 'before assignment'),
    ('while input():\n    x = 1\nprint(x)', 'before assignment'),
    ('def f(x):\n    return x\nf()', 'expects'),
    ('execute_query()', 'expects'),
    ('missing(input())', 'Undefined function'),
    ('return input()', 'outside a function'),
    ('def f():\n    pass\ndef f():\n    pass', 'Duplicate'),
    ('def f(x, x):\n    return x', 'Duplicate parameter'),
    ('def input():\n    pass', 'conflicting'),
    ('def f():\n    def g():\n        pass', 'Nested function'),
])
def test_semantic_failure(code, message):
    r = analyze(code)
    assert r.status == 'failed'
    assert any(message in d.message for d in r.semantic_issues)
    assert r.vulnerabilities == []
    assert 'SAFE' not in r.get_terminal_report()
    assert r.to_dict()['report_summary']['summary']['status'] == 'FAILED'


@pytest.mark.parametrize('code', ['x = @', 'x = "unterminated', 'if True:\n    x = 1\n  y = 2', 'if True:\n \tx = 1'])
def test_lexical_errors(code):
    with pytest.raises(LexerError):
        Lexer(code).tokenize()
    assert analyze(code).stages['lex'] == 'failed'


@pytest.mark.parametrize('code', ['if True\n    x = 1', 'x = (1 + )', 'def f(:\n    pass', 'x = 1 y = 2'])
def test_parse_errors(code):
    with pytest.raises(ParserError):
        Parser(Lexer(code).tokenize()).parse()
    assert analyze(code).stages['parse'] == 'failed'


def test_elif_precedence_and_locations():
    r = analyze('x = 2 + 3 * 4\nif x:\n    pass\nelif False:\n    pass\nelse:\n    pass')
    assert r.status == 'completed'
    expr = r.ast.body[0].value
    assert expr.op == '+' and expr.right.op == '*'
    assert r.ast.body[1].else_body[0].line == 4
    assert r.ast.to_dict()['body'][0]['col'] == 1


def test_lexer_values_comments_crlf():
    tokens = Lexer('x = 2.5 # comment\r\ny = "a\\n"\r\n').tokenize()
    assert [t.value for t in tokens if t.type == TokenType.NUMBER] == [2.5]
    assert [t.value for t in tokens if t.type == TokenType.STRING] == ['a\n']
    y = next(t for t in tokens if t.value == 'y')
    assert (y.line, y.col) == (2, 1)


def test_cfg_edges_and_function_return():
    r = analyze('def f(x):\n    while x:\n        x = x - 1\n    return x\na = input()\nif a:\n    b = a\nelse:\n    b = ""\nexecute_query(b)')
    data = r.to_dict()
    labels = [e['label'] for c in data['cfgs'].values() for e in c['edges']]
    assert {'True', 'False', 'LoopBack', 'Return'} <= set(labels)
    for cfg in r.cfgs.values():
        for b in cfg.blocks.values():
            for successor in b.successors:
                assert b in successor.predecessors


def test_loop_requires_second_visit():
    r = analyze('x = ""\ny = ""\ni = input()\nwhile i:\n    execute_query(y)\n    y = x\n    x = input()')
    assert len(r.vulnerabilities) == 1
    assert len(r.iteration_logs) > len(r.cfgs['main'].blocks)


@pytest.mark.parametrize('code', [
    'def f(x):\n    return f(x)\nexecute_query(f(input()))',
    'def f(x):\n    return g(x)\ndef g(x):\n    return f(x)\nf(input())',
    'x = ' + '(' * 300 + '1' + ')' * 300,
    'x' * 100001,
], ids=['recursive', 'mutual-recursion', 'deep-parse', 'oversized-source'])
def test_limits_are_explicit_failures(code):
    r = analyze(code)
    assert r.status == 'failed'
    assert not r.to_dict()['statistics']['converged']
    assert 'SAFE' not in r.get_terminal_report()


EXPECTED = {'slide_example.fg': ('completed', 1), 'command_injection.fg': ('completed', 1),
            'sanitized_safe.fg': ('completed', 0), 'interprocedural_call.fg': ('completed', 1),
            'loop_accumulation.fg': ('completed', 1), 'constant_reassignment.fg': ('completed', 0),
            'mismatched_sanitizer.fg': ('completed', 1), 'semantic_error.fg': ('failed', 0),
            'syntax_error.fg': ('failed', 0)}


@pytest.mark.parametrize('filename,expected', EXPECTED.items())
def test_examples(filename, expected):
    r = analyze((Path(__file__).resolve().parents[1] / 'examples' / filename).read_text())
    assert (r.status, len(r.vulnerabilities)) == expected
    if filename == 'slide_example.fg':
        f = r.vulnerabilities[0]
        assert (f.taint_record.source_line, f.sink_line) == (1, 8)


@pytest.fixture(scope='module')
def server_url():
    server = ThreadingHTTPServer(('127.0.0.1', 0), FlowGuardHTTPRequestHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    server.server_close()
    worker.join()


def test_api_analysis_and_health(server_url):
    assert json.load(urlopen(server_url + '/api/health'))['status'] == 'ok'
    assert 'slide_example.fg' in json.load(urlopen(server_url + '/api/examples'))
    request = Request(server_url + '/api/analyze', json.dumps({'code': 'execute_query(input())'}).encode(), {'Content-Type': 'application/json'})
    payload = json.load(urlopen(request))
    assert payload['data']['status'] == 'completed'
    assert len(payload['data']['findings']) == 1
    request = Request(server_url + '/api/analyze', b'{"code":"if :"}', {'Content-Type': 'application/json'})
    assert json.load(urlopen(request))['data']['status'] == 'failed'


@pytest.mark.parametrize('body', [b'not json', b'[]', b'{"code":42}', b'{"code":null}', b'{"code":"' + b'a' * 120001 + b'"}'], ids=['invalid-json','array','number-code','null-code','oversized-body'])
def test_api_bad_requests(server_url, body):
    with pytest.raises(HTTPError) as error:
        urlopen(Request(server_url + '/api/analyze', body, {'Content-Type': 'application/json'}))
    assert error.value.code in (400, 413)


def test_api_static_allowlist(server_url):
    for path in ('/', '/app.js', '/style.css'):
        assert urlopen(server_url + path).status == 200
    with pytest.raises(HTTPError) as error:
        urlopen(server_url + '/../../README.md')
    assert error.value.code == 404


@pytest.mark.parametrize('code', [
    'if False:\n    execute_query(input())',
    'while False:\n    execute_query(input())',
    'def f():\n    while True:\n        pass\n    execute_query(input())\nf()',
])
def test_literal_unreachable_flow(code):
    r = analyze(code)
    assert r.status == 'completed'
    assert not r.vulnerabilities


def test_reject_chained_comparison():
    assert analyze('x = 1 < 2 < 3').status == 'failed'


def test_diagnostic_stage_and_evidence_schema():
    error = analyze('if :').to_dict()
    assert error['diagnostics'][0]['stage'] == 'parse'
    assert error['semantic_diagnostics'] == []
    data = analyze('execute_query(input())').to_dict()
    assert data['findings'][0]['source_excerpt'] == 'execute_query(input())'
    assert data['findings'][0]['path'][0]['code'] == 'execute_query(input())'
    assert data['findings'][0]['id'] == analyze('execute_query(input())').to_dict()['findings'][0]['id']


@pytest.mark.parametrize('code', ['input = "x"\nexecute_query(input())', 'def f(input):\n    return input()\nf("x")'])
def test_function_names_cannot_be_shadowed(code):
    r = analyze(code)
    assert r.status == 'failed'
    assert any('shadow function names' in d.message for d in r.semantic_issues)
