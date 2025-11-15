#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
camocoat.py — lightweight ciphertext camouflage wrappers (PNG, PDF, ZIP, LOG)

Purpose:
  Wrap high-entropy ciphertext so it *looks* like ordinary files or text.
  This is metadata/traffic camouflage only; confidentiality is provided by your
  cipher engine (v3.6 or v3.5). Camocoat simply “dresses” the ciphertext.

Provided wrappers:
  - wrap_png(ct) / unwrap_png(blob)
      -> Valid PNG with a 1×1 pixel IHDR and a custom ancillary chunk ("stEG")
  - wrap_pdf(ct) / unwrap_pdf(blob)
      -> Minimal PDF with a single stream object holding the bytes
  - wrap_zip(ct, name="data.bin") / unwrap_zip(blob, name="data.bin")
      -> Valid ZIP containing a single stored file with your bytes
  - wrap_log(ct_b64) / unwrap_log(text)
      -> Log-like ASCII framing around Base64

Detection:
  - detect_format(blob_or_text) -> {"format": "png|pdf|zip|log|unknown"}
  - unwrap_auto(blob_or_text, **hints) -> raw ciphertext bytes or raises

Notes:
  - PNG & ZIP are binary-safe, good for email attachments.
  - PDF will “open” in many viewers (may show a blank page).
  - LOG is line-wrapped ASCII (great for email bodies).
  - All wrappers keep the ciphertext intact; no re-encoding except LOG (base64).

Limitations:
  - A determined analyst can still discover the trick (entropy, structure checks).
  - This is about *blending*, not perfect steganography.

(c) 2025 Robert Dowell. Educational use encouraged.
"""
from __future__ import annotations
import io, os, zlib, binascii, struct, zipfile, base64
from typing import Optional, Union, Tuple

# ---------- PNG wrapper ----------

_PNG_SIG = b"\x89PNG\r\n\x1a\n"

def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", binascii.crc32(ctype + data) & 0xffffffff)

def wrap_png(ciphertext: bytes, *, width: int = 1, height: int = 1) -> bytes:
    """Return a valid tiny PNG embedding ciphertext in a custom ancillary chunk 'stEG'."""
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    out = bytearray(_PNG_SIG)
    # Minimal IHDR: width/height, 8-bit RGBA, no interlace
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    out += _png_chunk(b'IHDR', ihdr)
    # A single transparent scanline to keep viewers quiet
    scanline = b"\x00" + b"\x00\x00\x00\x00" * height  # filter byte + RGBA zeros
    out += _png_chunk(b'IDAT', zlib.compress(scanline))
    # Ancillary custom chunk (lowercase first letter ==> ancillary)
    # Split to manageable pieces if very large (PNG allows multiple chunks)
    CHUNK = 64_000
    for i in range(0, len(ciphertext), CHUNK):
        out += _png_chunk(b'stEG', bytes(ciphertext[i:i+CHUNK]))
    out += _png_chunk(b'IEND', b'')
    return bytes(out)

def unwrap_png(png_bytes: bytes) -> bytes:
    """Extract concatenated 'stEG' chunk data from a PNG."""
    if not (isinstance(png_bytes, (bytes, bytearray)) and png_bytes.startswith(_PNG_SIG)):
        raise ValueError("not a PNG")
    off = len(_PNG_SIG)
    out = bytearray()
    while off + 8 <= len(png_bytes):
        (length,) = struct.unpack(">I", png_bytes[off:off+4]); off += 4
        ctype = png_bytes[off:off+4]; off += 4
        if off + length + 4 > len(png_bytes):  # truncated
            break
        payload = png_bytes[off:off+length]; off += length
        _crc = png_bytes[off:off+4]; off += 4
        if ctype == b'stEG':
            out.extend(payload)
        if ctype == b'IEND':
            break
    if not out:
        raise ValueError("no stEG chunk found")
    return bytes(out)

# ---------- PDF wrapper ----------

def wrap_pdf(ciphertext: bytes, *, title: str = "Report") -> bytes:
    """Minimal, well-formed PDF with one page and one stream object containing ciphertext."""
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    # Object numbers: 1 = catalog, 2 = pages, 3 = page, 4 = contents
    # We embed ciphertext as the content stream (not compressed) to keep simple.
    stream = ciphertext
    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
    xref = []
    def wobj(num: int, body: bytes):
        xref.append(pdf.tell())
        pdf.write(f"{num} 0 obj\n".encode("ascii"))
        pdf.write(body)
        pdf.write(b"\nendobj\n")
    # 1) Catalog
    wobj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    # 2) Pages
    wobj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3) Page (letter)
    wobj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>")
    # 4) Contents (our bytes)
    wobj(4, f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
    # xref
    xref_pos = pdf.tell()
    pdf.write(b"xref\n0 5\n")
    pdf.write(b"0000000000 65535 f \n")
    for pos in xref:
        pdf.write(f"{pos:010} 00000 n \n".encode("ascii"))
    # trailer
    pdf.write(b"trailer\n<< /Size 5 /Root 1 0 R /Info << /Title (")
    # Basic title escape
    pdf.write(title.encode("latin-1", errors="replace").replace(b")", b"\\)"))
    pdf.write(b") >> >>\nstartxref\n")
    pdf.write(f"{xref_pos}\n%%EOF\n".encode("ascii"))
    return pdf.getvalue()

def unwrap_pdf(pdf_bytes: bytes) -> bytes:
    """Pull raw bytes from the first 'stream...endstream' segment."""
    if not (isinstance(pdf_bytes, (bytes, bytearray)) and pdf_bytes.startswith(b"%PDF-")):
        raise ValueError("not a PDF")
    data = bytes(pdf_bytes)
    i = data.find(b"stream")
    if i < 0: raise ValueError("no stream found")
    i += len(b"stream")
    if i < len(data) and data[i:i+1] in (b"\r", b"\n"):  # skip immediate EOL
        i += 1
        if data[i-1:i] == b"\r" and data[i:i+1] == b"\n":
            i += 1
    j = data.find(b"endstream", i)
    if j < 0: raise ValueError("no endstream found")
    return data[i:j]

# ---------- ZIP wrapper ----------

def wrap_zip(ciphertext: bytes, *, name: str = "data.bin", compression: int = zipfile.ZIP_STORED) -> bytes:
    """Return a valid ZIP archive containing a single file <name> with our bytes."""
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        zf.writestr(name, ciphertext)
    return buf.getvalue()

def unwrap_zip(zip_bytes: bytes, *, name: str = "data.bin") -> bytes:
    """Extract <name> from a ZIP blob and return its bytes."""
    if not isinstance(zip_bytes, (bytes, bytearray)):
        raise TypeError("zip_bytes must be bytes")
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        with zf.open(name, "r") as f:
            return f.read()

# ---------- LOG wrapper (ASCII) ----------

def wrap_log(ciphertext_b64: Union[str, bytes], *, cols: int = 76, label: str = "system log") -> str:
    """ASCII log framing for Base64 ciphertext."""
    if isinstance(ciphertext_b64, bytes):
        try:
            ciphertext_b64 = ciphertext_b64.decode("ascii")
        except Exception:
            ciphertext_b64 = base64.b64encode(ciphertext_b64).decode("ascii")
    header = [
        f"-- START {label.upper()} --",
        "timestamp: N/A",
        "level: INFO",
        "payload_b64:",
    ]
    body = "\n".join(ciphertext_b64[i:i+cols] for i in range(0, len(ciphertext_b64), cols))
    footer = [
        "-- END LOG --"
    ]
    return "\n".join(header + [body] + footer) + "\n"

def unwrap_log(text: Union[str, bytes]) -> bytes:
    """Extract Base64 payload between 'payload_b64:' and '-- END LOG --'."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    start = text.find("payload_b64:")
    if start < 0:
        raise ValueError("no payload_b64 section")
    start = text.find("\n", start)
    if start < 0:
        raise ValueError("malformed log (no newline after payload_b64:)")
    end = text.find("-- END LOG --", start)
    payload = text[start:end if end > 0 else None]
    b64 = "".join(ch for ch in payload if ch.strip())
    return base64.b64decode(b64)

# ---------- Auto-detect & unwrap ----------

def detect_format(blob_or_text: Union[bytes, str]) -> dict:
    if isinstance(blob_or_text, (bytes, bytearray)):
        b = bytes(blob_or_text)
        if b.startswith(_PNG_SIG): return {"format": "png"}
        if b.startswith(b"%PDF-"): return {"format": "pdf"}
        if len(b) >= 4 and b[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return {"format": "zip"}
        # crude: if mostly printable ascii and contains payload marker
        try:
            s = b.decode("utf-8")
            if "payload_b64:" in s: return {"format": "log"}
        except Exception:
            pass
    else:
        if "payload_b64:" in str(blob_or_text): return {"format": "log"}
    return {"format": "unknown"}

def unwrap_auto(blob_or_text: Union[bytes, str], *, zip_name: str = "data.bin") -> bytes:
    kind = detect_format(blob_or_text)["format"]
    if kind == "png":
        return unwrap_png(blob_or_text if isinstance(blob_or_text, bytes) else blob_or_text.encode("latin-1"))
    if kind == "pdf":
        return unwrap_pdf(blob_or_text if isinstance(blob_or_text, bytes) else blob_or_text.encode("latin-1"))
    if kind == "zip":
        return unwrap_zip(blob_or_text if isinstance(blob_or_text, bytes) else blob_or_text.encode("latin-1"), name=zip_name)
    if kind == "log":
        return unwrap_log(blob_or_text)
    raise ValueError("unknown format; cannot unwrap")

# ---------- Tiny CLI (optional) ----------

def _cli():
    import argparse, sys, base64
    p = argparse.ArgumentParser(prog="camocoat", description="Ciphertext camouflage wrapper")
    sub = p.add_subparsers(dest="cmd", required=True)
    # wrap
    w = sub.add_parser("wrap", help="wrap ciphertext")
    w.add_argument("fmt", choices=["png","pdf","zip","log"])
    w.add_argument("infile")
    w.add_argument("outfile")
    w.add_argument("--zip-name", default="data.bin")
    w.add_argument("--title", default="Report")
    # unwrap
    u = sub.add_parser("unwrap", help="unwrap to raw ciphertext")
    u.add_argument("infile")
    u.add_argument("outfile")
    u.add_argument("--zip-name", default="data.bin")
    args = p.parse_args()

    data = open(args.infile, "rb").read()
    if args.cmd == "wrap":
        if args.fmt == "png":
            out = wrap_png(data)
        elif args.fmt == "pdf":
            out = wrap_pdf(data, title=args.title)
        elif args.fmt == "zip":
            out = wrap_zip(data, name=args.zip_name)
        else:
            # assume data is raw ciphertext; base64 for LOG
            out = wrap_log(base64.b64encode(data).decode("ascii")).encode("utf-8")
        open(args.outfile, "wb").write(out)
        print("Wrote:", args.outfile)
        return 0
    else:
        raw = unwrap_auto(data, zip_name=args.zip_name)
        open(args.outfile, "wb").write(raw)
        print("Wrote:", args.outfile)
        return 0

if __name__ == "__main__":
    raise SystemExit(_cli())
