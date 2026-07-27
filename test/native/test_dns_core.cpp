// Host-side unit tests for src/dns_core.h — the hashing, blocklist lookup and
// DNS packet handling the firmware runs on every query.
#include "../../src/dns_core.h"
#include "test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

using dnscore::HASH_BYTES;

// ---------- helpers ----------

// Stand-in for the flash blob: a sorted hash table backed by a byte buffer,
// read through the same little-endian decode the firmware uses.
struct FakeFlash {
  std::vector<uint8_t> bytes;
  uint32_t count = 0;

  void build(const std::vector<uint64_t>& hashes) {  // hashes must be sorted
    count = (uint32_t)hashes.size();
    bytes.assign(hashes.size() * HASH_BYTES, 0);
    for (size_t i = 0; i < hashes.size(); i++) dnscore::encodeHash(hashes[i], &bytes[i * HASH_BYTES]);
  }
  bool contains(uint64_t h) const {
    return dnscore::binarySearchHash(h, count, [this](uint32_t idx) {
      return dnscore::decodeHash(&bytes[idx * HASH_BYTES]);
    });
  }
};

static std::vector<uint8_t> query(const std::vector<std::string>& labels, uint16_t qtype = 1) {
  std::vector<uint8_t> pkt = {0xAB, 0xCD, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 0};
  for (const std::string& l : labels) {
    pkt.push_back((uint8_t)l.size());
    pkt.insert(pkt.end(), l.begin(), l.end());
  }
  pkt.push_back(0);
  pkt.push_back((uint8_t)(qtype >> 8)); pkt.push_back((uint8_t)(qtype & 0xFF));
  pkt.push_back(0); pkt.push_back(1);   // class IN
  return pkt;
}

static std::vector<uint64_t> sortedHashes(const std::vector<std::string>& domains) {
  std::vector<uint64_t> h;
  for (const std::string& d : domains) h.push_back(dnscore::fnv40(d.c_str(), d.size()));
  for (size_t i = 1; i < h.size(); i++)          // insertion sort, tiny inputs
    for (size_t j = i; j > 0 && h[j - 1] > h[j]; j--) { uint64_t t = h[j - 1]; h[j - 1] = h[j]; h[j] = t; }
  return h;
}

// ---------- fnv40 ----------

static void test_fnv40() {
  TEST_CASE("empty input is the plain FNV offset basis, truncated to 40 bits");
  CHECK_EQ_U64(dnscore::fnv40("", 0), 0xe484222325ULL);

  TEST_CASE("hashes stay inside 40 bits");
  const char* samples[] = {"a", "example.com", "doubleclick.net", "googleadservices.com",
                           "xn--80ak6aa92e.com", "sub.deep.tracker.io"};
  for (const char* s : samples) CHECK(dnscore::fnv40(s, strlen(s)) <= dnscore::HASH_MASK);

  TEST_CASE("matches the vectors shared with tools/build_blocklist.py");
  FILE* f = fopen("fixtures/hash_vectors.txt", "r");
  CHECK(f != nullptr);
  if (!f) return;
  char domain[256], hex[64]; int checked = 0;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    if (line[0] == '#' || line[0] == '\n') continue;
    if (sscanf(line, "%255s %63s", domain, hex) != 2) continue;
    CHECK_EQ_U64(dnscore::fnv40(domain, strlen(domain)), strtoull(hex, nullptr, 16));
    checked++;
  }
  fclose(f);
  CHECK(checked >= 5);

  TEST_CASE("different domains hash differently, case matters (callers lowercase first)");
  CHECK(dnscore::fnv40("ads.example.com", 15) != dnscore::fnv40("example.com", 11));
  CHECK(dnscore::fnv40("Example.com", 11) != dnscore::fnv40("example.com", 11));

  TEST_CASE("length is honoured, not the terminator");
  CHECK_EQ_U64(dnscore::fnv40("example.com/extra", 11), dnscore::fnv40("example.com", 11));
}

// ---------- hash encode / decode ----------

static void test_hash_codec() {
  TEST_CASE("round-trips every byte pattern that fits in 40 bits");
  const uint64_t vals[] = {0, 1, 0xFFULL, 0x0102030405ULL, dnscore::HASH_MASK};
  for (uint64_t v : vals) {
    uint8_t b[HASH_BYTES];
    dnscore::encodeHash(v, b);
    CHECK_EQ_U64(dnscore::decodeHash(b), v);
  }

  TEST_CASE("stores little-endian, matching the blob written by the builder");
  uint8_t b[HASH_BYTES];
  dnscore::encodeHash(0x0102030405ULL, b);
  CHECK_EQ_INT(b[0], 0x05); CHECK_EQ_INT(b[4], 0x01);

  TEST_CASE("bits above 40 are dropped, as they are by fnv40");
  dnscore::encodeHash(0xAA0102030405ULL, b);
  CHECK_EQ_U64(dnscore::decodeHash(b), 0x0102030405ULL);
}

// ---------- binary search ----------

static void test_binary_search() {
  FakeFlash flash;

  TEST_CASE("empty table never matches (the fail-open state during a swap)");
  flash.build({});
  CHECK(!flash.contains(0));
  CHECK(!flash.contains(dnscore::HASH_MASK));

  TEST_CASE("single entry");
  flash.build({42});
  CHECK(flash.contains(42));
  CHECK(!flash.contains(41)); CHECK(!flash.contains(43));

  TEST_CASE("finds every entry and rejects every gap");
  std::vector<uint64_t> table;
  for (uint64_t v = 0; v < 2000; v += 2) table.push_back(v);
  flash.build(table);
  for (uint64_t v = 0; v < 2000; v++) CHECK_EQ_INT(flash.contains(v), (v % 2) == 0);

  TEST_CASE("boundary values including the top of the 40-bit range");
  flash.build({0, 1, dnscore::HASH_MASK - 1, dnscore::HASH_MASK});
  CHECK(flash.contains(0)); CHECK(flash.contains(dnscore::HASH_MASK));
  CHECK(!flash.contains(2)); CHECK(!flash.contains(dnscore::HASH_MASK - 2));

  TEST_CASE("a table large enough for lo+hi to overflow a signed midpoint still resolves");
  uint32_t huge = 2000000000u;                      // far more entries than any real list
  uint32_t probeMax = 0;
  bool found = dnscore::binarySearchHash(huge - 2, huge, [&](uint32_t idx) -> uint64_t {
    if (idx > probeMax) probeMax = idx;
    return (uint64_t)idx;                           // table[i] == i
  });
  CHECK(found);
  CHECK(probeMax < huge);
}

// ---------- parent-domain matching ----------

static void test_is_blocked_domain() {
  FakeFlash flash;
  flash.build(sortedHashes({"doubleclick.net", "tracker.io"}));
  auto match = [&](uint64_t h) { return flash.contains(h); };

  TEST_CASE("exact match");
  CHECK(dnscore::isBlockedDomain("doubleclick.net", match));

  TEST_CASE("subdomains of a listed domain are blocked");
  CHECK(dnscore::isBlockedDomain("ad.g.doubleclick.net", match));
  CHECK(dnscore::isBlockedDomain("deep.sub.tracker.io", match));

  TEST_CASE("unrelated domains pass through");
  CHECK(!dnscore::isBlockedDomain("example.com", match));
  CHECK(!dnscore::isBlockedDomain("notdoubleclick.net", match));
  CHECK(!dnscore::isBlockedDomain("doubleclick.net.evil.com", match));

  TEST_CASE("the walk stops before the bare TLD pair, so a listed TLD suffix cannot over-block");
  FakeFlash tld;
  tld.build(sortedHashes({"net"}));
  auto tldMatch = [&](uint64_t h) { return tld.contains(h); };
  CHECK(!dnscore::isBlockedDomain("safe.example.net", tldMatch));

  TEST_CASE("a listed second-level domain still blocks its children");
  FakeFlash sld;
  sld.build(sortedHashes({"example.net"}));
  auto sldMatch = [&](uint64_t h) { return sld.contains(h); };
  CHECK(dnscore::isBlockedDomain("ads.example.net", sldMatch));
  CHECK(dnscore::isBlockedDomain("example.net", sldMatch));

  TEST_CASE("degenerate inputs");
  CHECK(!dnscore::isBlockedDomain("", match));
  CHECK(!dnscore::isBlockedDomain("localhost", match));

  TEST_CASE("each parent suffix is probed exactly once, cheapest first");
  std::vector<std::string> probed;
  dnscore::isBlockedDomain("a.b.c.example.com", [&](uint64_t) {
    probed.push_back("");
    return false;
  });
  CHECK_EQ_INT(probed.size(), 4);   // a.b.c.example.com, b.c.example.com, c.example.com, example.com
}

// ---------- DNS question parsing ----------

static void test_parse_query() {
  char out[256]; uint16_t qtype = 0; int qend = 0;

  TEST_CASE("plain A query");
  std::vector<uint8_t> pkt = query({"ads", "example", "com"});
  size_t n = dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_INT(n, 15);
  CHECK_EQ_STR(out, "ads.example.com");
  CHECK_EQ_INT(qtype, 1);
  CHECK_EQ_INT(qend, (int)pkt.size());

  TEST_CASE("qtype is read from the question, not assumed");
  pkt = query({"example", "com"}, 28);              // AAAA
  n = dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_INT(n, 11);
  CHECK_EQ_INT(qtype, 28);

  TEST_CASE("names are lowercased");
  pkt = query({"ADS", "Example", "COM"});
  dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_STR(out, "ads.example.com");

  TEST_CASE("a leading www. is stripped so www.x.com and x.com share a hash");
  pkt = query({"www", "example", "com"});
  n = dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_STR(out, "example.com");
  CHECK_EQ_INT(n, 11);

  TEST_CASE("www is only stripped as a prefix label");
  pkt = query({"wwwx", "example", "com"});
  dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_STR(out, "wwwx.example.com");

  TEST_CASE("single-label name");
  pkt = query({"localhost"});
  n = dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend);
  CHECK_EQ_INT(n, 9);
  CHECK_EQ_STR(out, "localhost");

  TEST_CASE("runt packets are rejected");
  uint8_t tiny[12] = {0};
  CHECK_EQ_INT(dnscore::parseQuery(tiny, 12, out, &qtype, &qend), 0);
  CHECK_EQ_INT(dnscore::parseQuery(tiny, 0, out, &qtype, &qend), 0);

  TEST_CASE("compressed names (0xC0 pointer) are rejected rather than followed");
  pkt = query({"example", "com"});
  pkt[12] = 0xC0;
  CHECK_EQ_INT(dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend), 0);

  TEST_CASE("a label running past the packet end is rejected");
  pkt = query({"example", "com"});
  pkt[12] = 60;                                     // claims 60 bytes of label
  CHECK_EQ_INT(dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend), 0);

  TEST_CASE("a question truncated before qtype/qclass is rejected");
  pkt = query({"example", "com"});
  pkt.resize(pkt.size() - 3);
  CHECK_EQ_INT(dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend), 0);

  TEST_CASE("an over-long name is rejected before it can overflow the caller's buffer");
  std::vector<std::string> many;
  for (int i = 0; i < 40; i++) many.push_back("abcdef");   // 40 * 7 = 280 bytes
  pkt = query(many);
  CHECK_EQ_INT(dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend), 0);

  TEST_CASE("a name just under the limit is still accepted");
  many.clear();
  for (int i = 0; i < 30; i++) many.push_back("abcdef");   // 30 * 7 - 1 = 209 bytes
  pkt = query(many);
  CHECK_EQ_INT(dnscore::parseQuery(pkt.data(), (int)pkt.size(), out, &qtype, &qend), 209);
}

// ---------- sinkhole answer ----------

static void test_build_blocked_response() {
  uint8_t buf[600];

  TEST_CASE("A query gets one answer record pointing at 0.0.0.0");
  std::vector<uint8_t> pkt = query({"ads", "example", "com"});
  memset(buf, 0, sizeof(buf));
  memcpy(buf, pkt.data(), pkt.size());
  int qend = (int)pkt.size();
  int len = dnscore::buildBlockedResponse(buf, qend, 1);

  CHECK_EQ_INT(len, qend + 16);
  CHECK_EQ_INT(buf[2], 0x81); CHECK_EQ_INT(buf[3], 0x80);   // QR + RD/RA, rcode NOERROR
  CHECK_EQ_INT(buf[7], 1);                                  // ANCOUNT
  CHECK_EQ_INT(buf[8], 0); CHECK_EQ_INT(buf[10], 0);        // NSCOUNT / ARCOUNT cleared
  CHECK_EQ_INT(buf[qend], 0xC0); CHECK_EQ_INT(buf[qend + 1], 0x0C);  // name pointer to the question
  CHECK_EQ_INT(buf[qend + 3], 1);                           // type A
  CHECK_EQ_INT(buf[qend + 5], 1);                           // class IN
  CHECK_EQ_INT(buf[qend + 9], 0x2C);                        // TTL 300s
  CHECK_EQ_INT(buf[qend + 11], 4);                          // RDLENGTH
  for (int i = 0; i < 4; i++) CHECK_EQ_INT(buf[qend + 12 + i], 0);   // 0.0.0.0

  TEST_CASE("the query id and question section are left untouched");
  CHECK_EQ_INT(buf[0], 0xAB); CHECK_EQ_INT(buf[1], 0xCD);
  CHECK_EQ_INT(buf[5], 1);                                  // QDCOUNT
  CHECK_EQ_INT(memcmp(buf + 12, pkt.data() + 12, pkt.size() - 12), 0);

  TEST_CASE("non-A queries get an empty NOERROR answer, no A record appended");
  memset(buf, 0, sizeof(buf));
  memcpy(buf, pkt.data(), pkt.size());
  len = dnscore::buildBlockedResponse(buf, qend, 28);        // AAAA
  CHECK_EQ_INT(len, qend);
  CHECK_EQ_INT(buf[7], 0);
  CHECK_EQ_INT(buf[qend], 0);                               // nothing written past the question
}

// ---------- end-to-end on the pure path ----------

static void test_query_to_answer() {
  FakeFlash flash;
  flash.build(sortedHashes({"doubleclick.net"}));
  uint8_t buf[600]; char domain[256]; uint16_t qtype = 0; int qend = 0;

  TEST_CASE("a query for a subdomain of a listed domain is sinkholed");
  std::vector<uint8_t> pkt = query({"www", "ad", "doubleclick", "net"});
  memcpy(buf, pkt.data(), pkt.size());
  size_t dl = dnscore::parseQuery(buf, (int)pkt.size(), domain, &qtype, &qend);
  CHECK_EQ_STR(domain, "ad.doubleclick.net");
  CHECK(dl > 0);
  CHECK(dnscore::isBlockedDomain(domain, [&](uint64_t h) { return flash.contains(h); }));
  CHECK_EQ_INT(dnscore::buildBlockedResponse(buf, qend, qtype), qend + 16);

  TEST_CASE("an unlisted domain is not sinkholed");
  pkt = query({"example", "com"});
  memcpy(buf, pkt.data(), pkt.size());
  dnscore::parseQuery(buf, (int)pkt.size(), domain, &qtype, &qend);
  CHECK(!dnscore::isBlockedDomain(domain, [&](uint64_t h) { return flash.contains(h); }));
}

int main() {
  RUN_SUITE(test_fnv40);
  RUN_SUITE(test_hash_codec);
  RUN_SUITE(test_binary_search);
  RUN_SUITE(test_is_blocked_domain);
  RUN_SUITE(test_parse_query);
  RUN_SUITE(test_build_blocked_response);
  RUN_SUITE(test_query_to_answer);
  return TEST_MAIN_RESULT();
}
