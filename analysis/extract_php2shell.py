#!/usr/bin/env python3
"""Pull PHP2Shell-shaped requests out of honeypot traffic.

Inputs (pick one):
  --raw DIR        directory of raw HTTP request files (tcpflow/-style dumps)
  --tshark FILE    output of: tshark -r x.pcap -Y 'http.request' -T json

Output: JSONL, one record per request, plus a summary to stderr.

This is an ANALYSIS tool. It recognises the published request shape; it does
not construct or send one.
"""
from __future__ import annotations
import argparse, json, re, sys, pathlib, collections, hashlib

UP_FIELD   = re.compile(rb"PHP_SESSION_UPLOAD_PROGRESS", re.I)
SESSID     = re.compile(rb"\bPHPSESSID\b", re.I)
FILENAME   = re.compile(rb'filename="([^"]*)"', re.I)
SERIALIZED = re.compile(rb"(O:\d+:|C:\d+:|a:\d+:\{|\x00)")
MULTIPART  = re.compile(rb"multipart/form-data", re.I)
SESSID_VAL = re.compile(rb"PHPSESSID[\"']?\s*[=:]?\s*[\r\n]*.*?([A-Za-z0-9,\-]{8,64})",
                        re.I | re.S)


def split_head_body(blob: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = blob.find(sep)
        if i != -1:
            return blob[:i], blob[i + len(sep):]
    return blob, b""


def score(head: bytes, body: bytes) -> tuple[int, list[str], dict]:
    ind: list[str] = []
    pts = 0
    meta: dict = {}
    is_post = head[:5].upper().startswith(b"POST")
    if is_post:
        ind.append("post")
    if MULTIPART.search(head):
        pts += 1; ind.append("multipart")
    if UP_FIELD.search(body):
        pts += 2; ind.append("upload_progress_field")
    body_sessid = bool(SESSID.search(body))
    head_sessid = bool(SESSID.search(head))
    if body_sessid:
        pts += 3; ind.append("sessid_in_body")
    if body_sessid and not head_sessid:
        pts += 1; ind.append("sessid_body_only")
    names = FILENAME.findall(body)
    meta["filenames"] = [n.decode("utf-8", "replace") for n in names[:8]]
    for n in names:
        if SERIALIZED.search(n):
            pts += 3; ind.append("serialized_in_filename"); break
    if any(len(n) > 120 for n in names):
        pts += 1; ind.append("overlong_filename")
    if len(body) > 512 * 1024:
        pts += 1; ind.append("large_body")
    m = SESSID_VAL.search(body) or SESSID_VAL.search(head)
    meta["session_id"] = m.group(1).decode() if m else None
    return pts, sorted(set(ind)), meta


def emit(src: str, blob: bytes, out) -> dict | None:
    head, body = split_head_body(blob)
    pts, ind, meta = score(head, body)
    if pts == 0:
        return None
    line = head.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    rec = {
        "source": src,
        "request_line": line.decode("utf-8", "replace")[:200],
        "score": pts,
        "verdict": "likely" if pts >= 6 else ("suspicious" if pts >= 3 else "weak"),
        "indicators": ind,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_len": len(body),
        **meta,
    }
    out.write(json.dumps(rec) + "\n")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=pathlib.Path)
    ap.add_argument("--tshark", type=pathlib.Path)
    a = ap.parse_args()
    if not (a.raw or a.tshark):
        ap.error("need --raw or --tshark")

    recs: list[dict] = []
    if a.raw:
        for f in sorted(a.raw.rglob("*")):
            if f.is_file():
                r = emit(str(f), f.read_bytes(), sys.stdout)
                if r:
                    recs.append(r)
    if a.tshark:
        data = json.loads(a.tshark.read_text())
        for i, pkt in enumerate(data):
            layers = pkt.get("_source", {}).get("layers", {})
            http = layers.get("http", {})
            raw = http.get("http.file_data") or ""
            hdrs = "".join(k for k in http if k.endswith("\\r\\n"))
            blob = (hdrs + "\r\n\r\n" + raw).encode("utf-8", "replace")
            r = emit(f"{a.tshark}#{i}", blob, sys.stdout)
            if r:
                recs.append(r)

    by_sess = collections.Counter(r["session_id"] for r in recs if r["session_id"])
    paired = {s: n for s, n in by_sess.items() if n >= 2}
    print(f"\n{len(recs)} scored request(s)", file=sys.stderr)
    for v in ("likely", "suspicious", "weak"):
        n = sum(1 for r in recs if r["verdict"] == v)
        if n:
            print(f"  {v:11s} {n}", file=sys.stderr)
    if paired:
        print(f"  sessions with 2+ requests (the two-request pattern): "
              f"{len(paired)}", file=sys.stderr)
        for s, n in list(paired.items())[:10]:
            print(f"    {s}  x{n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
