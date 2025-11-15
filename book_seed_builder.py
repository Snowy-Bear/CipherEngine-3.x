#!/usr/bin/env python3
"""
Book Seed Builder (pure stdlib)
- Interactive script: user picks ONLINE (fetch & clean pages) or OFFLINE (local text file).
- Produces a curated, normalized ~1 MiB byte stream suitable as input to Keybook's snapshot step.
- No third-party libraries required (urllib + html.parser).

Outputs:
  - book_seed.txt   (normalized UTF-8 text, exactly TARGET_SIZE bytes)
  - seed_audit.json (sources and stats)

You can also import this file and call build_book_seed(...) programmatically.

Copyright:
  (c) 2025 Robert Dowell. Educational use encouraged.
"""

from __future__ import annotations
import os, re, time, json, random, hashlib, urllib.request, urllib.parse
from typing import List, Dict, Tuple, Optional
from html.parser import HTMLParser
from html import unescape

# -------------------------
# Tunables
# -------------------------
TARGET_SIZE = 1 * 1024 * 1024  # 1 MiB
MIN_PAGE_BYTES = 4 * 1024      # discard tiny pages after cleaning
CHUNK_MIN = 4 * 1024           # chunk size range to interleave variety
CHUNK_MAX = 12 * 1024
REQUEST_TIMEOUT = 10
REQUEST_DELAY_RANGE = (0.6, 1.4)  # polite randomized delay between requests
USER_AGENT = "KeybookSeedBuilder/1.0 (+educational; stdlib; politely fetching a few pages)"
# Tunables
PER_HINT_MAX_DEFAULT = 3     # polite default
GLOBAL_MAX_PAGES     = 30    # hard ceiling across all hints
EARLY_STOP_BYTES     = TARGET_SIZE * 2  # stop fetching once we have ample material

# Default online sources (you can add more)
SEARCHERS = {
    "wikipedia": "https://en.wikipedia.org/w/index.php?search={query}",
}
WIKI_HOSTS = ("en.wikipedia.org",)


# -------------------------
# Utilities
# -------------------------

def _normalize_text(txt: str) -> str:
    """Lowercase, collapse whitespace, normalize to simple UTF-8 text lines."""
    txt = txt.replace("\r\n", "\n").replace("\r", "\n")
    txt = unescape(txt)
    txt = txt.lower()
    txt = re.sub(r"[ \t]+", " ", txt)
    txt = re.sub(r"\n\s+\n", "\n\n", txt)
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    return txt.strip()

class _TextExtractor(HTMLParser):
    """HTML → visible text. Skips script/style/nav tags."""
    SKIP = {"script", "style", "noscript"}
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self._skip = 0
        self._buf: List[str] = []
    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip > 0:
            self._skip -= 1
    def handle_data(self, data):
        if self._skip == 0:
            self._buf.append(data + " ")
    def get_text(self) -> str:
        return "".join(self._buf)

def _extract_visible_text(html_bytes: bytes) -> str:
    try:
        txt = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""
    p = _TextExtractor()
    p.feed(txt)
    return _normalize_text(p.get_text())

def _http_get(url: str) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            return resp.read()
    except Exception:
        return None

def _polite_sleep():
    time.sleep(random.uniform(*REQUEST_DELAY_RANGE))

def _find_wikipedia_article_urls(search_html: str, limit: int = 3) -> List[str]:
    """
    Very simple url finder for wiki result pages: look for '/wiki/...' links.
    (No external parsing libs; regex is acceptable here as we're scanning for links.)
    """
    urls: List[str] = []
    for m in re.finditer(r'href="/wiki/([^":#?]+)"', search_html):
        path = m.group(1)
        if ":" in path:
            continue
        url = f"https://en.wikipedia.org/wiki/{path}"
        urls.append(url)
        if len(urls) >= limit:
            break
    return urls

def _chunk_bytes(b: bytes, min_size=CHUNK_MIN, max_size=CHUNK_MAX) -> List[bytes]:
    out: List[bytes] = []
    i = 0
    rng = random.Random(hashlib.sha256(b[:32]).digest())
    while i < len(b):
        size = rng.randint(min_size, max_size)
        out.append(b[i:i+size])
        i += size
    return out

def _dedup_chunks(chunks: List[bytes], window=512) -> List[bytes]:
    """
    Drop near-duplicates by hashing first window bytes of each chunk.
    Simple & cheap; enough to cut repeats without heavy processing.
    """
    seen = set()
    out: List[bytes] = []
    for c in chunks:
        w = c[:window]
        h = hashlib.sha1(w).digest()
        if h in seen:
            continue
        seen.add(h)
        out.append(c)
    return out

def _interleave_and_pack(chunks: List[bytes], target_size: int = TARGET_SIZE) -> bytes:
    random.shuffle(chunks)
    if not chunks:
        return (b"\n" * target_size)[:target_size]
    buf = bytearray()
    n = len(chunks)
    i = 0
    while len(buf) < target_size:
        buf.extend(chunks[i % n])
        i += 1
    out = bytes(buf[:target_size])
    return out if len(out) == target_size else (out + b"\n" * target_size)[:target_size]

# -------------------------
# ONLINE builder  (polite caps + early stop)
# -------------------------

def build_online(hints: List[str], per_hint: int = PER_HINT_MAX_DEFAULT) -> Tuple[bytes, List[Dict]]:
    """
    Fetch a few Wikipedia pages per hint, extract text, normalize, dedup, chunk, interleave, pack.
    Returns (book_seed_bytes, sources_audit).
    """
    per_hint = max(1, min(int(per_hint), 5))  # clamp to [1..5]
    audit: List[Dict] = []
    all_chunks: List[bytes] = []
    fetched_pages = 0

    for hint in hints:
        if fetched_pages >= GLOBAL_MAX_PAGES:
            break
        q = hint.strip()
        if not q:
            continue

        search_url = SEARCHERS["wikipedia"].format(query=urllib.parse.quote(q))
        _polite_sleep()
        html = _http_get(search_url)
        if not html:
            continue
        search_text = html.decode("utf-8", errors="ignore")
        cand_urls = _find_wikipedia_article_urls(search_text, limit=per_hint)

        for url in cand_urls:
            if fetched_pages >= GLOBAL_MAX_PAGES:
                break
            _polite_sleep()
            page = _http_get(url)
            if not page:
                continue
            text = _extract_visible_text(page)
            b = text.encode("utf-8", errors="ignore")
            if len(b) < MIN_PAGE_BYTES:
                continue

            chunks = _chunk_bytes(b)
            all_chunks.extend(chunks)
            audit.append({
                "title": url.rsplit("/", 1)[-1].replace("_", " "),
                "url": url,
                "content_hash": hashlib.sha256(b).hexdigest(),
                "bytes": len(b)
            })
            fetched_pages += 1

            # Early stop if we’ve gathered enough material
            # (look only at a slice to keep this cheap)
            if sum(len(c) for c in all_chunks[:200]) >= EARLY_STOP_BYTES:
                break

    if not all_chunks:
        raise RuntimeError("Online builder found no usable pages. Try different hints or offline mode.")

    random.shuffle(all_chunks)
    unique_chunks = _dedup_chunks(all_chunks)
    seed_bytes = _interleave_and_pack(unique_chunks, target_size=TARGET_SIZE)
    return seed_bytes, audit


# -------------------------
# OFFLINE builder
# -------------------------

def build_offline(path: str) -> Tuple[bytes, List[Dict]]:
    """
    Read a local UTF-8 text file, normalize, chunk, dedup, interleave, pack.
    Recommend providing at least ~2–4 MiB of raw text for variety.
    Returns (book_seed_bytes, sources_audit).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such file: {path}")

    raw = open(path, "rb").read()
    try:
        txt = raw.decode("utf-8", errors="ignore")
    except Exception:
        txt = raw.decode("latin-1", errors="ignore")

    norm = _normalize_text(txt)
    b = norm.encode("utf-8")
    if len(b) < MIN_PAGE_BYTES:
        raise RuntimeError("Offline file too small after normalization; pick a larger source.")

    chunks = _chunk_bytes(b)
    unique_chunks = _dedup_chunks(chunks)
    seed_bytes = _interleave_and_pack(unique_chunks, target_size=TARGET_SIZE)
    audit = [{
        "title": os.path.basename(path),
        "url": f"file://{os.path.abspath(path)}",
        "content_hash": hashlib.sha256(b).hexdigest(),
        "bytes": len(b),
    }]
    return seed_bytes, audit

# -------------------------
# Top-level entry
# -------------------------

def build_book_seed(mode: str,
                    hints: Optional[List[str]] = None,
                    offline_path: Optional[str] = None) -> Tuple[bytes, List[Dict]]:
    """
    Programmatic API:
      - mode='online' with hints=[...]  -> fetch & build
      - mode='offline' with offline_path=... -> read & build
    """
    mode = (mode or "").strip().lower()
    if mode == "online":
        if not hints or all(not h.strip() for h in hints):
            raise ValueError("Provide at least one non-empty hint for online mode")
        return build_online([h for h in hints if h.strip()])
    elif mode == "offline":
        if not offline_path:
            raise ValueError("Provide offline_path for offline mode")
        return build_offline(offline_path)
    else:
        raise ValueError("mode must be 'online' or 'offline'")

# -------------------------
# Interactive CLI-ish loop
# -------------------------

def _interactive():
    print("Book Seed Builder")
    print("=================")
    print("Choose mode: (O)nline (Wikipedia by default) or (F)ile (offline corpus)")
    while True:
        m = input("[O/F]? ").strip().lower()
        if m in ("o", "f"):
            break

    if m == "o":
        print("\nEnter 3–10 hints (blank line to finish):")
        hints: List[str] = []
        while True:
            line = input("> ").strip()
            if not line:
                break
            hints.append(line)
            if len(hints) >= 10:
                break
        if len(hints) < 1:
            print("No hints provided; aborting.")
            return
        print("\nFetching a few pages per hint (polite delays)...")
        try:
            seed, audit = build_online(hints)
        except Exception as e:
            print("Failed to build online seed:", e)
            return
    else:
        path = input("Path to UTF-8 text file (>= ~2–4 MiB recommended): ").strip()
        try:
            seed, audit = build_offline(path)
        except Exception as e:
            print("Failed to build offline seed:", e)
            return

    # Write outputs
    out_txt = "book_seed.txt"
    out_audit = "seed_audit.json"
    with open(out_txt, "wb") as f:
        f.write(seed)
    with open(out_audit, "w", encoding="utf-8") as f:
        json.dump({
            "size_bytes": len(seed),
            "sources": audit
        }, f, indent=2)

    print(f"\nDone.\n - Seed text: {out_txt} ({len(seed)} bytes)")
    print(f" - Audit:     {out_audit}")
    print("You can now feed book_seed.txt to your Keybook snapshot step.")

if __name__ == "__main__":
    try:
        _interactive()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
