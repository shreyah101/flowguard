"""Local-only standard-library HTTP API. Submitted programs are never executed."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import sys
from flowguard.analyzer import FlowGuardAnalyzer

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / 'web'
EXAMPLES_DIR = BASE_DIR.parent / 'examples'
MAX_BODY = 120000


def load_presets() -> dict[str, str]:
    return {p.name: p.read_text(encoding='utf-8') for p in sorted(EXAMPLES_DIR.glob('*.fg'))}


class FlowGuardHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def respond(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ('/api/presets', '/api/examples'):
            self.respond(load_presets())
        elif self.path == '/api/health':
            self.respond({'status': 'ok', 'analyzer': 'FlowGuard'})
        elif self.path in ('/', '/index.html', '/style.css', '/app.js'):
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if self.path != '/api/analyze':
            self.respond({'success': False, 'error': 'Unknown endpoint'}, 404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > MAX_BODY:
                self.respond({'success': False, 'error': 'Request body must be 1..120000 bytes'}, 413)
                return
            self.connection.settimeout(10)
            data = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(data, dict) or not isinstance(data.get('code'), str):
                raise ValueError('Expected a JSON object with a string code field')
        except (ValueError, UnicodeError, TimeoutError):
            self.respond({'success': False, 'error': 'Invalid request: expected JSON with a string code field'}, 400)
            return
        try:
            result = FlowGuardAnalyzer().analyze(data['code'])
            self.respond({'success': True, 'data': result.to_dict(),
                          'terminal_report': result.get_terminal_report()})
        except Exception:
            self.respond({'success': False, 'error': 'Internal analysis error; no security conclusion is available'}, 500)


def start_server(port: int = 8080) -> None:
    with ThreadingHTTPServer(('127.0.0.1', port), FlowGuardHTTPRequestHandler) as server:
        print(f'FlowGuard workbench: http://127.0.0.1:{port} (Ctrl+C to stop)')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('FlowGuard stopped.')


if __name__ == '__main__':
    start_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
