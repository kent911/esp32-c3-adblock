// Minimal host-side test harness: no dependencies, so `make -C test` works on a
// bare machine (and in CI) without pulling in a unit-test framework.
#pragma once

#include <stdio.h>
#include <string.h>

namespace testutil {

inline int& failures() { static int n = 0; return n; }
inline const char*& currentCase() { static const char* name = "?"; return name; }

inline void fail(const char* file, int line, const char* expr, const char* detail) {
  failures()++;
  printf("  FAIL %s\n    %s:%d: %s%s%s\n", currentCase(), file, line, expr,
         detail && detail[0] ? " -> " : "", detail ? detail : "");
}

}  // namespace testutil

#define TEST_CASE(name) \
  testutil::currentCase() = (name); \
  printf("  case %s\n", (name));

#define CHECK(expr) \
  do { if (!(expr)) testutil::fail(__FILE__, __LINE__, #expr, ""); } while (0)

#define CHECK_EQ_U64(actual, expected)                                         \
  do {                                                                         \
    unsigned long long a_ = (unsigned long long)(actual);                      \
    unsigned long long e_ = (unsigned long long)(expected);                    \
    if (a_ != e_) {                                                            \
      char d_[96]; snprintf(d_, sizeof(d_), "got %llu (0x%llx), want %llu", a_, a_, e_); \
      testutil::fail(__FILE__, __LINE__, #actual, d_);                         \
    }                                                                          \
  } while (0)

#define CHECK_EQ_INT(actual, expected)                                         \
  do {                                                                         \
    long a_ = (long)(actual); long e_ = (long)(expected);                      \
    if (a_ != e_) {                                                            \
      char d_[96]; snprintf(d_, sizeof(d_), "got %ld, want %ld", a_, e_);      \
      testutil::fail(__FILE__, __LINE__, #actual, d_);                         \
    }                                                                          \
  } while (0)

#define CHECK_EQ_STR(actual, expected)                                         \
  do {                                                                         \
    const char* a_ = (actual); const char* e_ = (expected);                    \
    if (strcmp(a_, e_) != 0) {                                                 \
      char d_[256]; snprintf(d_, sizeof(d_), "got \"%s\", want \"%s\"", a_, e_); \
      testutil::fail(__FILE__, __LINE__, #actual, d_);                         \
    }                                                                          \
  } while (0)

#define RUN_SUITE(fn)  do { printf("%s\n", #fn); fn(); } while (0)

#define TEST_MAIN_RESULT()                                                     \
  (testutil::failures() == 0                                                   \
       ? (printf("\nall checks passed\n"), 0)                                  \
       : (printf("\n%d check(s) failed\n", testutil::failures()), 1))
