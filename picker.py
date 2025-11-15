#!/usr/bin/env python3
"""
pickfile.py — tiny console file picker for Pythonista / pure Python (hardened to current directory)

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

import os
import pathlib
import time
from typing import Sequence, Optional, List

def _norm_exts(extensions: Optional[Sequence[str]]) -> Optional[List[str]]:
    if not extensions:
        return None
    out: List[str] = []
    for ext in extensions:
        e = (ext or "").strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        out.append(e)
    return out or None

def _ls_filtered(extensions: Optional[Sequence[str]] = None) -> List[pathlib.Path]:
    exts = _norm_exts(extensions)
    here = pathlib.Path(".")
    items: List[pathlib.Path] = []
    for name in os.listdir(here):
        p = here / name
        if not p.is_file():
            continue
        if exts and p.suffix.lower() not in exts:
            continue
        items.append(p)
    # newest first
    items.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return items

def _sanitise_manual_name(name: str) -> Optional[str]:
    """Reject path traversal and directory components; return basename or None."""
    if not name:
        return None
    # forbid separators / traversal
    if "/" in name or "\\" in name or ".." in name:
        return None
    # collapse to just a filename
    return os.path.basename(name).strip()

def _find_case_insensitive_in_cwd(basename: str) -> Optional[pathlib.Path]:
    """Search ONLY the current directory for a case-insensitive basename match."""
    here = pathlib.Path(".")
    target = basename.lower()
    for f in os.listdir(here):
        if f.lower() == target:
            p = here / f
            if p.is_file():
                return p
    return None

def pick_file(
    prompt: str = "Select file",
    extensions: Optional[Sequence[str]] = None,
    show: int = 12
) -> pathlib.Path:
    """
    Interactive picker: lists recent files (filtered), lets user type a number or a name.
    Selection is confined to the current directory. The extensions filter is enforced for
    both list and manual selection.
    """
    norm_exts = _norm_exts(extensions)
    files = _ls_filtered(norm_exts)
    print(f"\n{prompt}")
    if norm_exts:
        print("Allowed:", ", ".join(norm_exts))
    if not files:
        raise FileNotFoundError("No matching files in this folder.")

    for i, p in enumerate(files[:show], 1):
        try:
            st = p.stat()
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
            print(f"{i:2d}) {p.name:40}  {ts}  {st.st_size} bytes")
        except FileNotFoundError:
            # File vanished between list and stat; skip it
            continue

    print("Enter a number from the list, or type a filename (case-insensitive, current folder only).")
    while True:
        try:
            choice = input("> ").strip()
        except KeyboardInterrupt:
            print("\nCancelled.")
            raise SystemExit(1)

        if not choice:
            print("Please enter a number or filename.")
            continue

        # Numeric pick
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= min(show, len(files)):
                return files[idx - 1]
            print("Out of range, try again.")
            continue

        # Manual filename pick (confined to cwd)
        base = _sanitise_manual_name(choice)
        if not base:
            print("Invalid name (no paths or '..' allowed). Try again.")
            continue

        p = _find_case_insensitive_in_cwd(base)
        if p and p.is_file():
            if norm_exts and p.suffix.lower() not in norm_exts:
                print(f"File exists but not in allowed extensions {norm_exts}.")
                continue
            return p

        print("Not found. Try again (number or filename).")
