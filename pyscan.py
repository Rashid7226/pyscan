#!/usr/bin/env python3
"""
Pyscan Safe - production-oriented malware signature scanner for Linux hosting servers.

Based on the uploaded Pyscan prototype, with safer operational behavior:
- Python 3
- HTTPS signature retrieval with local cache
- configurable maximum file size (default 20 MiB)
- hash blacklist/whitelist support
- regex signature scoring
- no automatic file modification
- optional quarantine
- per-account/path scanning
- bounded worker count
- scan/error/skip statistics
"""

import argparse
import datetime as dt
import hashlib
import logging
import os
import queue
import re
import shutil
import ssl
import sys
import tempfile
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

VERSION = "2.0-safe"
DEFAULT_MAX_SIZE = 20 * 1024 * 1024
DEFAULT_WORKERS = max(1, min((os.cpu_count() or 2), 4))
CACHE_DIR = "/var/cache/pyscan"
LOG_FILE = "/var/log/pyscan.log"

# HTTPS sources from the first uploaded version.
PATTERN_URL = "https://codesilo.dimenoc.com/abuse/shellscanner-patterns/raw/master/ShellScannerPatterns"
MD5_URL = "https://codesilo.dimenoc.com/stephend/pyscan/raw/master/md5_blacklist"
SHA1_WL_URL = "https://codesilo.dimenoc.com/abuse/shellscanner-patterns/raw/master/pyscan-sha1.whitelist"
SHA1_BL_URL = "https://codesilo.dimenoc.com/abuse/shellscanner-patterns/raw/master/pyscan-sha1.blacklist"

stats_lock = threading.Lock()
stats = {"scanned": 0, "hits": 0, "errors": 0, "skipped": 0}

def log(msg, level=logging.INFO):
    logging.log(level, msg)

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def download(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "pyscan-safe/2.0"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read()

def cached_download(url, name, refresh=False):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    cache = os.path.join(CACHE_DIR, name)
    if not refresh and os.path.isfile(cache) and os.path.getsize(cache) > 0:
        return Path(cache).read_bytes()
    data = download(url)
    fd, tmp = tempfile.mkstemp(prefix=name + ".", dir=CACHE_DIR)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, cache)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return data

def load_signatures(refresh=False):
    try:
        pattern_data = cached_download(PATTERN_URL, "ShellScannerPatterns", refresh).decode("utf-8", "replace")
        md5_data = cached_download(MD5_URL, "md5_blacklist", refresh).decode("utf-8", "replace")
        sha1_wl_data = cached_download(SHA1_WL_URL, "pyscan-sha1.whitelist", refresh).decode("utf-8", "replace")
        sha1_bl_data = cached_download(SHA1_BL_URL, "pyscan-sha1.blacklist", refresh).decode("utf-8", "replace")
    except Exception as e:
        raise RuntimeError(f"Unable to download signatures: {e}")

    signatures = []
    for line in pattern_data.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        try:
            left, regex = line.split("|", 1)
            score_part = left.split("-_")[1].split(":")[1]
            score = int(score_part)
            tag = left.split("_-")[0]
            name = left.split("_-")[1].split("-_")[0]
            signatures.append((tag, name, score, regex))
        except Exception:
            log(f"Skipping malformed signature line: {line[:120]}", logging.WARNING)

    compiled = []
    for tag, name, score, regex in signatures:
        try:
            compiled.append((tag, name, score, re.compile(regex, re.MULTILINE | re.UNICODE)))
        except re.error as e:
            raise RuntimeError(f"Invalid signature {name}: {e}")

    md5_blacklist = {x.split()[0].lower() for x in md5_data.splitlines() if x.strip()}
    sha1_whitelist = {x.split()[0].lower() for x in sha1_wl_data.splitlines() if x.strip()}
    sha1_blacklist = {x.split()[0].lower() for x in sha1_bl_data.splitlines() if x.strip()}

    return compiled, md5_blacklist, sha1_whitelist, sha1_blacklist

def iter_files(paths, excludes, max_size, exclude_root_owner):
    excludes = [os.path.realpath(x) for x in excludes]
    for base in paths:
        base = os.path.realpath(os.path.abspath(os.path.expanduser(base)))
        if not os.path.exists(base):
            log(f"Path not found: {base}", logging.WARNING)
            continue

        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            real_root = os.path.realpath(root)
            dirs[:] = [d for d in dirs
                       if os.path.realpath(os.path.join(root, d)) not in excludes]

            for name in files:
                p = os.path.join(root, name)
                try:
                    st = os.lstat(p)
                    if not stat_is_regular(st.st_mode):
                        continue
                    if st.st_size > max_size:
                        with stats_lock:
                            stats["skipped"] += 1
                        continue
                    if exclude_root_owner and st.st_uid == 0 and st.st_gid == 0:
                        with stats_lock:
                            stats["skipped"] += 1
                        continue
                    yield p
                except OSError:
                    with stats_lock:
                        stats["errors"] += 1

def stat_is_regular(mode):
    return (mode & 0o170000) == 0o100000

def scan_file(path, compiled, md5_blacklist, sha1_whitelist, sha1_blacklist):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except (OSError, IOError) as e:
        with stats_lock:
            stats["errors"] += 1
        return None, f"I/O error: {path}: {e}"

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()

    if md5 in md5_blacklist:
        return {
            "path": path, "type": "MD5_BLACKLIST", "score": 100,
            "confidence": "VERYHIGH", "signatures": ["MD5_BLACKLIST"]
        }, None

    if sha1 in sha1_whitelist:
        with stats_lock:
            stats["scanned"] += 1
        return None, None

    if sha1 in sha1_blacklist:
        return {
            "path": path, "type": "SHA1_BLACKLIST", "score": 100,
            "confidence": "VERYHIGH", "signatures": ["SHA1_BLACKLIST"]
        }, None

    # Decode conservatively. Replacement avoids failures on binary/non-UTF8 files.
    text = data.decode("utf-8", "replace")
    score = 0
    hits = []

    for tag, name, sig_score, regex in compiled:
        try:
            if regex.search(text):
                score += sig_score
                hits.append(f"{name}:{sig_score}")
        except Exception as e:
            return None, f"Regex error on {path}: {e}"

    with stats_lock:
        stats["scanned"] += 1

    if not hits:
        return None, None

    if score >= 10:
        confidence = "VERYHIGH"
    elif score > 5:
        confidence = "HIGH"
    elif score == 5:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "path": path,
        "type": "SIGNATURE",
        "score": score,
        "confidence": confidence,
        "signatures": hits,
    }, None

def quarantine(path, quarantine_dir):
    os.makedirs(quarantine_dir, mode=0o700, exist_ok=True)
    base = os.path.basename(path)
    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    dest = os.path.join(quarantine_dir, f"{stamp}_{base}")
    try:
        shutil.move(path, dest)
        os.chmod(dest, 0o600)
        return dest
    except OSError as e:
        return f"FAILED: {e}"

def main():
    parser = argparse.ArgumentParser(description="Safe Pyscan malware signature scanner")
    parser.add_argument("-p", "--path", action="append", default=[], help="Path to scan")
    parser.add_argument("-u", "--user", action="append", default=[], help="cPanel username; scans /home/USER/public_html")
    parser.add_argument("--exclude", action="append", default=[], help="Directory to exclude")
    parser.add_argument("-x", "--exclude-root-owner", action="store_true", help="Skip root:root files")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_WORKERS, help="Worker threads (default: %(default)s)")
    parser.add_argument("--max-size-mb", type=int, default=20, help="Maximum file size in MB (default: 20)")
    parser.add_argument("--refresh-signatures", action="store_true", help="Refresh signature cache")
    parser.add_argument("--quarantine", metavar="DIR", help="Move detected files to this directory; OFF by default")
    parser.add_argument("--dry-run", action="store_true", help="Report detections without changing files (default behavior)")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("Run as root.")

    if not args.path and not args.user:
        args.path = ["/home"]

    paths = list(args.path)
    for user in args.user:
        paths.append(f"/home/{user}/public_html")

    threads = max(1, min(args.threads, 8))
    max_size = args.max_size_mb * 1024 * 1024

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
    )

    log(f"Pyscan Safe {VERSION} starting")
    log(f"Paths: {', '.join(paths)}")
    log(f"Max file size: {args.max_size_mb} MB; workers: {threads}")

    compiled, md5_bl, sha1_wl, sha1_bl = load_signatures(args.refresh_signatures)
    log(f"Loaded {len(compiled)} regex signatures, {len(md5_bl)} MD5 blacklist entries, "
        f"{len(sha1_bl)} SHA1 blacklist entries, {len(sha1_wl)} SHA1 whitelist entries")

    files = list(iter_files(paths, args.exclude, max_size, args.exclude_root_owner))
    log(f"Files queued: {len(files)}")

    hits = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_file, p, compiled, md5_bl, sha1_wl, sha1_bl): p
            for p in files
        }
        for future in as_completed(futures):
            result, error = future.result()
            if error:
                log(error, logging.WARNING)
            if result:
                hits.append(result)
                with stats_lock:
                    stats["hits"] += 1
                log(f"HIT [{result['confidence']}] score={result['score']} "
                    f"file={result['path']} signatures={','.join(result['signatures'])}")

    if args.quarantine and hits:
        log(f"Quarantine requested: {args.quarantine}")
        for result in hits:
            # Only quarantine actual files that still exist.
            if os.path.isfile(result["path"]):
                destination = quarantine(result["path"], args.quarantine)
                log(f"QUARANTINE {result['path']} -> {destination}")

    log("=" * 70)
    log(f"Scan complete. Scanned={stats['scanned']} Hits={stats['hits']} "
        f"Skipped={stats['skipped']} Errors={stats['errors']}")
    log("=" * 70)

if __name__ == "__main__":
    main()
