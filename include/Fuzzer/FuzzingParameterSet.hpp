/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_
#define BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_

#include <random>
#include <unordered_map>

#include "Utilities/Range.hpp"
#include "Utilities/Enums.hpp"

class FuzzingParameterSet {
 private:
  std::mt19937 gen;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval.
  int num_refresh_intervals;

  /// The numbers of aggressors to be picked from during random pattern generation.
  int num_aggressors;

  int agg_intra_distance;

  int agg_inter_distance;

  // initialized with -1 to add check for undefined/default value
  int num_activations_per_tREFI = -1;

  int hammering_total_num_activations;

  int base_period;

  int max_row_no;

  int total_acts_pattern;

  Range<int> start_row;

  Range<int> num_aggressors_for_sync;

  Range<int> bank_no;

  Range<int> use_sequential_aggressors;

  Range<int> amplitude;

  Range<int> N_sided;

  Range<int> sync_each_ref;

  Range<int> wait_until_start_hammering_refs;

  std::discrete_distribution<int> N_sided_probabilities;

  [[nodiscard]] std::string get_dist_string() const;

  void set_distribution(Range<int> range_N_sided, std::unordered_map<int, int> probabilities);

 public:
  FuzzingParameterSet() = default;

  explicit FuzzingParameterSet(int measured_num_acts_per_ref);

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  [[nodiscard]] int get_hammering_total_num_activations() const;

  [[nodiscard]] int get_num_aggressors() const;

  int get_random_amplitude(int max);

  int get_random_N_sided();

  [[nodiscard]] int get_base_period() const;

  [[nodiscard]] int get_agg_intra_distance();

  [[nodiscard]] int get_agg_inter_distance() const;

  int get_random_even_divisior(int n, int min_value);

  int get_random_N_sided(int upper_bound_max);

  int get_random_start_row();

  [[nodiscard]] int get_num_activations_per_t_refi() const;

  [[nodiscard]] int get_total_acts_pattern() const;

  bool get_random_use_seq_addresses();

  bool get_random_sync_each_ref();

  void randomize_parameters(bool print = true);

  [[nodiscard]] int get_max_row_no() const;

  int get_random_num_aggressors_for_sync();

  int get_random_wait_until_start_hammering_us();

  [[nodiscard]] int get_num_refresh_intervals() const;

  [[nodiscard]] int get_num_base_periods() const;

  void set_total_acts_pattern(int pattern_total_acts);

  void set_hammering_total_num_activations(int hammering_total_acts);

  void set_agg_intra_distance(int agg_intra_dist);

  void set_agg_inter_distance(int agg_inter_dist);

  void set_use_sequential_aggressors(const Range<int> &use_seq_addresses);

  void print_semi_dynamic_parameters() const;

  void print_static_parameters() const;

  static void print_dynamic_parameters(int bank, bool seq_addresses, int start_row);

  static void print_dynamic_parameters2(bool sync_at_each_ref, int wait_until_hammering_us, int num_aggs_for_sync);

  void set_num_activations_per_t_refi(int num_activations_per_t_refi);
};

#endif //BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_
