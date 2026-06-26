# esp32-c3-adblock

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3** — *no PSRAM required*.

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 64-bit hashes in flash** and binary-search them. 130,000+ domains
fit in ~1 MB of flash and are matched in microseconds, using **~40 KB of RAM**.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search the flash hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

## Why this is interesting

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
demand an ESP32-S3 with 4–8 MB of **PSRAM**. This project stores fixed **8-byte
hashes in flash** instead:

| | string-in-RAM approach | this (hash-in-flash) |
|---|---|---|
| Hardware | ESP32-S3 + 8 MB PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| 130k domains | several MB of RAM | **1.02 MB of flash** |
| RAM used | most of it | **~40 KB** |
| Lookup | string compare | ~17 cached-flash reads (µs) |
| Collisions | n/a | 0 (64-bit hash) |

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.

## Build & flash (PlatformIO)

One USB flash to get going — after that, **firmware and blocklist both update over WiFi** (see below).

```bash
# 1. set your WiFi creds (secrets.h is gitignored, so they stay local)
cp src/secrets.example.h src/secrets.h
#    then edit src/secrets.h -> WIFI_SSID / WIFI_PASS

# 2. build the blocklist hash table (default = StevenBlack base + Hagezi Light,
#    ~140k domains, WhatsApp/social safe)
python3 tools/build_blocklist.py data/blocklist.bin

# 3. flash firmware + the blocklist filesystem (the one and only USB flash)
pio run -t upload
pio run -t uploadfs

# 4. watch it boot, note the IP / open the dashboard
pio device monitor          # -> http://c3adblock.local
```

## Over-the-air updates (no more USB)

The dashboard at **http://c3adblock.local** does it all:

- **Blocklist** — drop a freshly built `blocklist.bin` into *Blocklist → Upload*, or set a
  URL under *Remote auto-update* and the device pulls a prebuilt `blocklist.bin`
  on a schedule (e.g. a GitHub release asset — update it once, every device fetches it).
- **Firmware** — upload `.pio/build/c3/firmware.bin` under *Firmware → OTA update*; the
  device verifies it and reboots into the new image. Or push over WiFi from the CLI:
  ```bash
  pio run -t upload --upload-port c3adblock.local --upload-protocol espota
  ```

**4 MB flash tradeoff:** firmware OTA needs *two* app slots, which leaves ~1.3 MB for the
blocklist (**~250k domains max**). The aggressive 537k "ultimate" list only fits the
single-app partition table (no firmware OTA). Pick your tradeoff in `partitions.csv`.

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Done / how it could grow

- ✅ Web dashboard — per-client block/allow counts, ban a client, add custom domains
- ✅ mDNS (`c3adblock.local`) for discovery
- ✅ OTA — firmware + blocklist update over WiFi, plus scheduled remote blocklist pulls
- ⬜ Bloom filter in RAM as a fast pre-filter (skip flash for the ~99% of misses)
- ⬜ Act as the DHCP server (hand itself out as DNS) for true plug-and-play

## Credits

Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch
implementation focused on the hash-in-flash optimization for PSRAM-less chips.

## License

MIT — see [LICENSE](LICENSE).
