/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#ifdef ENABLE_JITTING
#include <asmjit/asmjit.h>
#endif

#include <algorithm>
#include <iostream>
#include <random>

#include "Fuzzer/HammeringPattern.hpp"
#include "Utilities/Range.hpp"

class PatternBuilder {
 private:
  HammeringPattern &pattern;

  std::mt19937 gen;

  int aggressor_id_counter;

  static int get_next_prefilled_slot(size_t cur_idx, std::vector<int> start_indices_prefilled_slots, int base_period,
                              int &cur_prefilled_slots_idx);

 public:
  /// default constructor that randomizes fuzzing parameters
  explicit PatternBuilder(HammeringPattern &hammering_pattern);

  void generate_frequency_based_pattern(FuzzingParameterSet &params, int pattern_length, int base_period);

  void generate_frequency_based_pattern(FuzzingParameterSet &params);

  size_t get_random_gaussian(std::vector<int> &list);

  static void remove_smaller_than(std::vector<int> &vec, int N);

  static int all_slots_full(size_t offset, size_t period, int pattern_length, std::vector<Aggressor> &aggs);

  static void fill_slots(size_t start_period,
                         size_t period_length,
                         size_t amplitude,
                         std::vector<Aggressor> &aggressors,
                         std::vector<Aggressor> &accesses,
                         size_t pattern_length);

  void get_n_aggressors(size_t N, std::vector<Aggressor> &aggs);

  void prefill_pattern(int pattern_total_acts, std::vector<AggressorAccessPattern> &fixed_aggs);

  static std::vector<int> get_available_multiplicators(FuzzingParameterSet &fuzzing_params);

  static std::vector<int> get_available_multiplicators(int num_base_periods);
};

#endif /* PATTERNBUILDER */
