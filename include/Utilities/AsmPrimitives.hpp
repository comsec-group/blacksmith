/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef UTILS
#define UTILS

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <unordered_map>

#include "GlobalDefines.hpp"

[[gnu::unused]] static inline __attribute__((always_inline)) void clflush(volatile void *p) {
  asm volatile("clflush (%0)\n"::"r"(p)
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void clflushopt(volatile void *p) {
#ifdef DDR3
  asm volatile("clflush (%0)\n" ::"r"(p)
               : "memory");
#else
  asm volatile("clflushopt (%0)\n"::"r"(p)
  : "memory");
#

#endif
}

[[gnu::unused]] static inline __attribute__((always_inline)) void cpuid() {
  asm volatile("cpuid"::
  : "rax", "rbx", "rcx", "rdx");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void mfence() {
  asm volatile("mfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void sfence() {
  asm volatile("sfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void lfence() {
  asm volatile("lfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t rdtscp() {
  uint64_t lo, hi;
  asm volatile("rdtscp\n"
  : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32UL) | lo;
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t rdtsc() {
  uint64_t lo, hi;
  asm volatile("rdtsc\n"
  : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32UL) | lo;
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t realtime_now() {
  struct timespec now_ts{};
  clock_gettime(CLOCK_MONOTONIC, &now_ts);
  return static_cast<uint64_t>(
      (static_cast<double>(now_ts.tv_sec)*1e9 + static_cast<double>(now_ts.tv_nsec)));
}

#endif /* UTILS */
