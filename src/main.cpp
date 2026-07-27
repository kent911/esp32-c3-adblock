// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "dns_core.h"   // pure hashing / DNS logic, unit-tested natively (test/native)
#include "secrets.h"   // WIFI_SSID / WIFI_PASS / DASH_USER / DASH_PASS / OTA_PASS — copy secrets.example.h and fill in
#include "util.h"      // shared fs / domain / formatting helpers

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_TMP_PATH = "/blocklist.new";
static const char* CUSTOM_PATH = "/custom.txt";
static const char* BANNED_PATH = "/banned.txt";
static const char* UPDATE_CFG_PATH = "/update.cfg";
static const int HASH_BYTES = dnscore::HASH_BYTES;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0, totalFailed = 0;
uint8_t buf[600];
bool fsReady = false;

// Serial is the only channel for background faults; rate-limit so a stuck
// subsystem can't drown the console (or stall DNS) with one line per query.
static void logThrottled(uint32_t& last, const char* msg) {
  uint32_t now = millis();
  if (last && now - last < 5000) return;
  last = now ? now : 1;
  Serial.println(msg);
}

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// ---------- hashing / matching ----------
using dnscore::fnv40;
static bool inFlash(uint64_t h) {
  if (!blocklist || !numHashes) return false;
  static uint32_t lastReadErr = 0;
  return dnscore::binarySearchHash(h, numHashes, [](uint32_t idx) {
    uint8_t b[HASH_BYTES];
    if (!blocklist.seek(idx * HASH_BYTES) ||
        blocklist.read(b, HASH_BYTES) != HASH_BYTES) {
      logThrottled(lastReadErr, "[blocklist] flash read failed -> fail-open");
      return uint64_t(0);
    }
    return dnscore::decodeHash(b);
  });
}
static bool inCustom(uint64_t h) { return indexOfValue(customHash, numCustom, h) >= 0; }
static bool isBlocked(const char* domain) {
  return dnscore::isBlockedDomain(domain, [](uint64_t h) { return inFlash(h) || inCustom(h); });
}

// ---------- persistence ----------
static void saveCustom() { fsWriteLines(CUSTOM_PATH, numCustom, [](int i) { return customDom[i]; }); }
static bool addCustomEntry(const String& d) {   // in-memory insert, no flash write
  if (!isValidDomain(d) || numCustom >= MAX_CUSTOM) return false;
  if (indexOfValue(customDom, numCustom, d) >= 0) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++;
  return true;
}
static void loadCustom() {
  numCustom = 0;
  if (!fsReady) return;
  fsReadLines(CUSTOM_PATH, [](const String& l) { 
    addCustomEntry(normalizeDomain(l)); 
    return numCustom < MAX_CUSTOM; 
  });
}
// Returns nullptr on success, otherwise a human-readable reason.
static const char* addCustom(String d) {
  if (!fsReady) return "filesystem not ready";
  String normalized = normalizeDomain(d);
  if (normalized.length() == 0) return "not a domain";
  if (numCustom >= MAX_CUSTOM) return "custom list full";
  if (indexOfValue(customDom, numCustom, normalized) >= 0) return "already blocked";
  
  if (!addCustomEntry(normalized)) return "failed to add domain";
  saveCustom(); 
  return nullptr;
}
static const char* removeCustom(String d) {
  if (!fsReady) return "filesystem not ready";
  String normalized = normalizeDomain(d);
  int i = indexOfValue(customDom, numCustom, normalized);
  if (i < 0) return "not in the custom list";
  
  int nDom = numCustom, nHash = numCustom;
  removeAt(customDom, nDom, i); removeAt(customHash, nHash, i);
  numCustom = nDom;
  saveCustom();
  return nullptr;
}
static bool isBannedIP(uint32_t ip) { return indexOfValue(bannedIP, numBanned, ip) >= 0; }
static void loadBanned() {
  numBanned = 0;
  if (!fsReady) return;
  fsReadLines(BANNED_PATH, [](const String& l) {
    IPAddress ip;
    if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip;
    return numBanned < MAX_BAN;
  });
}
static bool saveBanned() {
  if (!fsReady) return false;
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) {
    if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  }
  fsWriteLines(BANNED_PATH, numBanned, [](int i) { return IPAddress(bannedIP[i]).toString(); });
  return true;
}

