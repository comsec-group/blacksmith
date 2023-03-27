/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>
#include <random>

#include "Utilities/AsmPrimitives.hpp"
#include "Utilities/BlacksmithConfig.hpp"

class DramAnalyzer {
 private:
  BlacksmithConfig &config;

  volatile char *start_address;

  std::mt19937 gen;

  std::uniform_int_distribution<int> dist;

 public:
  explicit DramAnalyzer(BlacksmithConfig &config, volatile char *target);

  /// Measures the time between accessing two addresses.
  static inline uint64_t measure_time(volatile char *a1, volatile char *a2, size_t rounds);

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_trefi();

  static size_t count_acts_per_trefi(volatile char *a, volatile char*b);
};

#endif /* DRAMANALYZER */
