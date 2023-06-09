#!/usr/bin/env python
# Path: scripts/makebuild.py

"""Clean project's working directory"""

import os
import shutil

EXTS_TO_REMOVE = [".log", ".pyc", ".pyo", "_pb2.py"]

DIRS_TO_REMOVE = [
    ".venv",
    "dist",
    "docs",
    "whiteproto/_proto/_compiled/org",
]

SUBDIRS_TO_REMOVE = [
    "__pycache__",
    ".mypy_cache",
]

print("[i] Cleaning directories...")
for _dir in DIRS_TO_REMOVE:
    if os.path.exists(_dir):
        shutil.rmtree(_dir)


print("[i] Cleaning caches...")
for root, dirs, files in os.walk("."):
    for _file in files:
        for ext in EXTS_TO_REMOVE:
            if _file.endswith(ext):
                os.remove(os.path.join(root, _file))
    for _dir in dirs:
        if _dir in SUBDIRS_TO_REMOVE:
            shutil.rmtree(os.path.join(root, _dir))

print("[i] Cleaning done.")
