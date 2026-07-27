#pragma once
// Small shared helpers used across the firmware: LittleFS line-oriented
// persistence, domain normalisation, array lookups, JSON/HTTP formatting.

#include <Arduino.h>
#include <LittleFS.h>
#include <WebServer.h>
#include "dns_core.h"   // pure helpers, unit-tested natively (test/native)

// ---------- LittleFS text files ----------
// Every persisted control file (custom domains, banned IPs, update config) is a
// newline-delimited text blob. Lines are trimmed and handed to onLine, which
// returns false to stop reading. Empty lines are passed through so positional
// files (update.cfg) keep their line numbering.
// Returns false if the file could not be opened (missing file included, which is
// normal on first boot -- callers that care log it themselves).
template <typename Fn>
static bool fsReadLines(const char* path, Fn onLine) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (!onLine(line)) break;
  }
  f.close();
  return true;
}

// Rewrites path with count lines produced by lineAt(i). False means the file is
// now short or missing: a full/worn flash makes println() write less than asked.
template <typename Fn>
static bool fsWriteLines(const char* path, int count, Fn lineAt) {
  File f = LittleFS.open(path, "w");
  if (!f) { Serial.printf("[fs] %s: open for write failed\n", path); return false; }
  bool ok = true;
  for (int i = 0; i < count; i++) {
    String line = lineAt(i);
    ok = (f.println(line) == line.length() + 2) && ok;
  }
  f.close();
  if (!ok) Serial.printf("[fs] %s: write failed (flash full?)\n", path);
  return ok;
}

// ---------- domains ----------
// Same normalisation as tools/build_blocklist.py norm(): lowercase, no leading
// wildcard/dot, no trailing dot, no "www." prefix.
static String normalizeDomain(const String& d) {
  char out[256];
  return String(dnscore::normalizeDomain(d.c_str(), out, sizeof(out)));
}
// A domain label set: letters, digits, '-', '.'. Anything else (quotes, angle
// brackets, control chars) is rejected so stored values can never carry markup.
static bool isValidDomain(const String& d) { return dnscore::validDomain(d.c_str(), d.length()); }

// ---------- arrays ----------
template <typename T>
static int indexOfValue(const T* arr, int count, const T& v) {
  for (int i = 0; i < count; i++) if (arr[i] == v) return i;
  return -1;
}
// Removes element i by shifting the tail down; count is decremented in place.
template <typename T>
static void removeAt(T* arr, int& count, int i) {
  for (int j = i; j < count - 1; j++) arr[j] = arr[j + 1];
  count--;
}

// ---------- formatting ----------
static String macToString(const uint8_t* m) {
  char s[18];
  snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(s);
}
static String uptimeToString(uint32_t seconds) {
  char s[24];
  snprintf(s, sizeof(s), "%lud %luh %lum", seconds / 86400, (seconds % 86400) / 3600, (seconds % 3600) / 60);
  return String(s);
}
static String jsonEscape(const String& s) { String o; dnscore::appendJsonEscaped(o, s.c_str()); return o; }
static String jsonString(const String& s) { return "\"" + jsonEscape(s) + "\""; }

// ---------- web replies ----------
static void sendResult(WebServer& w, bool ok, const String& okMsg, const String& errMsg) {
  w.send(ok ? 200 : 500, "text/plain", ok ? okMsg : errMsg);
}
