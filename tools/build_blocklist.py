#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [--allow-partial] [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Pro) ~= 200k domains: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  A source that fails to download aborts the build (exit 1) so a half-built
  list never overwrites a good one -- pass --allow-partial to build anyway.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt
"""
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~140k domains / 0.67 MB.
# Want more (up to ~250k)? swap light.txt -> pro.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt',  # Hagezi Light
]

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    args = sys.argv[1:]
    allow_partial = '--allow-partial' in args
    args = [a for a in args if a != '--allow-partial']
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains = set()
    failed = []
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! failed {src}: {e}', file=sys.stderr); failed.append(src); continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or line[0] in '!/':
                continue
            parts = line.split()
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') \
                else parts[0] if len(parts) == 1 else None
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)

    if failed and not allow_partial:
        sys.exit(f'error: {len(failed)}/{len(sources)} source(s) unreachable, '
                 f'{out} left untouched (use --allow-partial to override)')
    if not domains:
        sys.exit('error: no domains parsed from any source, refusing to write an empty blocklist')

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    tmp = out + '.tmp'                               # write-then-replace: an interrupted
    with open(tmp, 'wb') as f:                       # run can't leave a truncated blob
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, out)

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')
    if failed:
        print(f'PARTIAL BUILD    : {len(failed)} source(s) failed: {", ".join(failed)}', file=sys.stderr)

if __name__ == '__main__':
    main()
