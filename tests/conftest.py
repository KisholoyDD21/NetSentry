"""Shared pytest fixtures for the NetSentry test suite."""
import sys
from pathlib import Path

# Make the `netsentry` package importable when running `pytest` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
