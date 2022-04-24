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

class DramAnalyzer {
 private:
  std::vector<std::vector<volatile char *>> banks;

  std::vector<uint64_t> bank_rank_functions;

  uint64_t row_function;

  volatile char *start_address;

  void find_targets(std::vector<volatile char *> &target_bank);

  std::mt19937 gen;

  std::uniform_int_distribution<int> dist;

 public:
  explicit DramAnalyzer(volatile char *target);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  /// Measures the time between accessing two addresses.
  static int inline measure_time(volatile char *a1, volatile char *a2) {
    uint64_t before, after;
    before = rdtscp();
    lfence();
    for (size_t i = 0; i < DRAMA_ROUNDS; i++) {
      (void)*a1;
      (void)*a2;
      clflushopt(a1);
      clflushopt(a2);
      mfence();
    }
    after = rdtscp();
    return (int) ((after - before)/DRAMA_ROUNDS);
  }

  std::vector<uint64_t> get_bank_rank_functions();

  void load_known_functions(int num_ranks);

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_trefi();
};

#endif /* DRAMANALYZER */
