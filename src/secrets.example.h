#pragma once
// Copy this file to secrets.h and fill in your own values.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Dashboard login (HTTP basic auth) — protects stats, ban, custom domains,
// blocklist upload and firmware OTA. Leave DASH_PASS empty only on a network
// you fully trust: an empty password disables the dashboard login.
static const char* DASH_USER = "admin";
static const char* DASH_PASS = "CHANGE_ME";

// Password for network firmware flashing (pio ... --upload-protocol espota).
// Empty = espota disabled.
static const char* OTA_PASS = "CHANGE_ME";
