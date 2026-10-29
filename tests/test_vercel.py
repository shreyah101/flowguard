"""Exercise each Vercel export over HTTP using the real shared handler."""
import importlib
import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
import pytest


@pytest.mark.parametrize('endpoint', ['health', 'examples', 'presets', 'analyze'])
def test_vercel_entrypoint(endpoint):
    exported = importlib.import_module('api.' + endpoint).handler
    server = ThreadingHTTPServer(('127.0.0.1', 0), exported)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f'http://127.0.0.1:{server.server_port}/api/{endpoint}'
        if endpoint == 'analyze':
            request = Request(url, json.dumps({'code': 'execute_query(input())'}).encode(), {'Content-Type': 'application/json'})
            data = json.load(urlopen(request))
            assert data['data']['status'] == 'completed'
            assert len(data['data']['findings']) == 1
        elif endpoint == 'health':
            assert json.load(urlopen(url))['status'] == 'ok'
        else:
            assert 'slide_example.fg' in json.load(urlopen(url))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
