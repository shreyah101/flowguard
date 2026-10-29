"""Vercel discovers this explicit class; shared API behavior stays in FlowGuard."""
from flowguard.server import FlowGuardHTTPRequestHandler


class handler(FlowGuardHTTPRequestHandler):
    """Expose the existing validated HTTP handler as a Vercel Python function."""
