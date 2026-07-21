"""Vercel-compatible entrypoint.

Exports the FastAPI app object at module level so platforms that import
`app.py` can load the ASGI application without extra configuration.
"""

from src.app import app

__all__ = ["app"]
