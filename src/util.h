#pragma once
// Small shared helpers used across the firmware: LittleFS line-oriented
// persistence, domain normalisation, array lookups, JSON/HTTP formatting.

#include <Arduino.h>
#include <LittleFS.h>
#include <WebServer.h>

// ---------- LittleFS text files ----------
// Every persisted control file (custom domains, banned IPs, update config) is a
// newline-delimited text blob. Lines are trimmed and handed to onLine, which
// returns false to stop reading. Empty lines are passed through so positional
// files (update.cfg) keep their line numbering.
template <typename Fn>
static void fsReadLines(const char* path, Fn onLine) {
  File f = LittleFS.open(path, "r");
  if (!f) return;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (!onLine(line)) break;
  }
  f.close();
}

// Rewrites path with count lines produced by lineAt(i).
template <typename Fn>
static bool fsWriteLines(const char* path, int count, Fn lineAt) {
  File f = LittleFS.open(path, "w");
  if (!f) return false;
  for (int i = 0; i < count; i++) f.println(lineAt(i));
  f.close();
  return true;
}

// ---------- domains ----------
// Same normalisation as tools/build_blocklist.py norm(): lowercase, no leading
// wildcard/dot, no trailing dot, no "www." prefix.
static String normalizeDomain(String d) {
  d.trim();
  d.toLowerCase();
  while (d.startsWith("*") || d.startsWith(".")) d = d.substring(1);
  while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
  if (d.startsWith("www.")) d = d.substring(4);
  return d;
}
static bool isValidDomain(const String& d) {
  return d.length() && d.indexOf('.') > 0 && d.indexOf(' ') < 0;
}

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
static String jsonEscape(const String& s) {
  String o;
  for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; }
  return o;
}
static String jsonString(const String& s) { return "\"" + jsonEscape(s) + "\""; }

// ---------- web replies ----------
static void sendPlain(WebServer& w, const String& msg) { w.send(200, "text/plain", msg); }
static void sendResult(WebServer& w, bool ok, const String& okMsg, const String& errMsg) {
  w.send(ok ? 200 : 500, "text/plain", ok ? okMsg : errMsg);
}
