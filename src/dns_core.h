// Pure logic shared by the firmware and the native unit tests: hashing,
// blocklist lookup and the minimal DNS packet parsing/answer building.
// Deliberately free of Arduino/ESP headers so it compiles on the host.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace dnscore {

static const int HASH_BYTES = 5;                                  // 40-bit, must match tools/build_blocklist.py
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const size_t MAX_DOMAIN_LEN = 250;                         // bytes written to the caller's buffer, excl. NUL

inline uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}

// One blocklist entry as stored in flash: HASH_BYTES little-endian bytes.
inline uint64_t decodeHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
inline void encodeHash(uint64_t h, uint8_t* out) {
  for (int k = 0; k < HASH_BYTES; k++) out[k] = (uint8_t)((h >> (8 * k)) & 0xFF);
}

// readHash(index) -> uint64_t, over an ascending-sorted table of `count` hashes.
template <typename ReadHash>
inline bool binarySearchHash(uint64_t h, uint32_t count, ReadHash readHash) {
  int32_t lo = 0, hi = (int32_t)count - 1;
  while (lo <= hi) {
    int32_t mid = (int32_t)(((uint32_t)lo + (uint32_t)hi) >> 1);
    uint64_t v = readHash((uint32_t)mid);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}

// Blocks a domain if it or any of its parent domains (down to, but excluding,
// the bare TLD label pair) is listed. match(hash) -> bool.
template <typename Match>
inline bool isBlockedDomain(const char* domain, Match match) {
  const char* p = domain;
  while (p && *p) {
    if (match(fnv40(p, strlen(p)))) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// Reads the QNAME of the first question into `out` (lowercased, dot-joined,
// leading "www." stripped) and reports the query type plus the offset just past
// the question. Returns the domain length, or 0 if the packet is unusable
// (truncated, compressed name, over-long domain).
inline size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= MAX_DOMAIN_LEN || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) {
      uint8_t c = pkt[i++];
      out[o++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (uint16_t)((pkt[i] << 8) | pkt[i + 1]);
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}

// Turns the query already sitting in `buf` into the sinkhole reply: 0.0.0.0 for
// an A query, otherwise an empty NOERROR answer. Returns the reply length.
inline int buildBlockedResponse(uint8_t* buf, int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80;
  buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0;
  buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans));
  return qend + (int)sizeof(ans);
}

// Accepts only what a stored/serialised domain may contain: lowercase letters,
// digits, '-' and '.', with no leading/trailing/doubled dot. Keeps markup and
// control characters out of custom.txt and of the dashboard JSON.
inline bool validDomain(const char* d, size_t n) {
  if (n < 3 || n > 253) return false;
  if (d[0] == '.' || d[n - 1] == '.') return false;
  bool hasDot = false;
  for (size_t i = 0; i < n; i++) {
    char ch = d[i];
    bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.';
    if (!ok) return false;
    if (ch == '.') { if (i && d[i - 1] == '.') return false; hasDot = true; }
  }
  return hasDot;
}

// Same normalisation as tools/build_blocklist.py norm(): trim, lowercase, drop
// leading '*'/'.' and trailing '.', drop a "www." prefix. Writes into `out`
// (capacity `cap`, including the NUL) and returns it; input longer than the
// buffer is truncated.
inline const char* normalizeDomain(const char* in, char* out, size_t cap) {
  const char* end = in + strlen(in);
  while (in < end && (uint8_t)*in <= ' ') in++;
  while (end > in && (uint8_t)end[-1] <= ' ') end--;
  size_t n = (size_t)(end - in);
  if (n > cap - 1) n = cap - 1;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
  }
  size_t start = 0;
  while (start < n && (out[start] == '*' || out[start] == '.')) start++;
  while (n > start && out[n - 1] == '.') n--;
  if (n - start >= 4 && strncmp(out + start, "www.", 4) == 0) start += 4;
  n -= start;
  memmove(out, out + start, n);
  out[n] = 0;
  return out;
}

// Appends `s` to `out` (Arduino String or std::string) escaped for a JSON
// string literal.
template <typename Str>
inline void appendJsonEscaped(Str& out, const char* s) {
  for (const char* p = s; *p; p++) {
    char ch = *p;
    if (ch == '"' || ch == '\\') { out += '\\'; out += ch; }
    else if ((uint8_t)ch < 0x20) {
      const char* hex = "0123456789abcdef";
      out += '\\'; out += 'u'; out += '0'; out += '0';
      out += hex[((uint8_t)ch >> 4) & 0xF]; out += hex[(uint8_t)ch & 0xF];
    }
    else out += ch;
  }
}

}  // namespace dnscore
