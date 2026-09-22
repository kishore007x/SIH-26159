"""
Vercel serverless adapter for SecureMailScope FastAPI app.
Wraps the FastAPI app with Mangum for Vercel Functions (Python runtime).
"""
import os
import sys

# Ensure the project root is on sys.path so bare `backend.*` imports resolve.
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from mangum import Mangum
from backend.main import app

# Read environment from Vercel's mechanism (process env / .env file is also supported
# by pydantic-settings on import, but Vercel sets vars directly in the runtime).
handler = Mangum(app, lifespan="auto")
