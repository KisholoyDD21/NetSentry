"""
Shared utilities: config loading, logging setup, helper functions.
"""
from __future__ import annotations

import json
import logging
import math
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def get_project_root() -> Path:
    """Return the project root regardless of the current working directory."""
    return Path(__file__).resolve().parent.parent


def resolve_path(relative_path: str) -> Path:
    root = get_project_root()
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATH = "config.json"
_config_cache: dict | None = None


def load_config(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    full_path = get_project_root() / path
    if not full_path.exists():
        raise FileNotFoundError(f"Config file not found: {full_path}")

    with open(full_path, "r", encoding="utf-8") as f:
        _config_cache = json.load(f)
    return _config_cache


def reload_config(path: str = _DEFAULT_CONFIG_PATH) -> dict:
    global _config_cache
    _config_cache = None
    return load_config(path)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logger(name: str = "netsentry") -> logging.Logger:
    config = load_config()
    log_cfg = config.get("logging", {})
    log_path = resolve_path(log_cfg.get("path", "logs/netsentry.log"))
    level_name = log_cfg.get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)

    logger = logging.getLogger(name)
    if logger.handlers:
        # Already configured (avoid duplicate handlers on repeated calls)
        return logger

    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    return logger


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def is_private_ip(ip: str) -> bool:
    """Lightweight private/reserved IPv4 check without extra dependencies."""
    try:
        octets = [int(o) for o in ip.split(".")]
        if len(octets) != 4:
            return True  # not a normal IPv4 -> treat as non-public / skip
    except ValueError:
        return True

    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 0:
        return True
    return False


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string -- used as a lightweight DGA-domain signal."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:3.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def ensure_dirs():
    """Create runtime directories referenced by config.json if missing."""
    config = load_config()
    resolve_path(config["database"]["path"])
    resolve_path(config["logging"]["path"])
    resolve_path(config["reports"]["export_dir"] + "/.keep")
