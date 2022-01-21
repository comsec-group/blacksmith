/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

#include <unordered_set>

struct SweepSummary {
  // Number of observed corruptions from zero to one.
  size_t num_flips_z2o;

  // Number of observed corruptions from one to zero.
  size_t num_flips_o2z;

  std::vector<BitFlip> observed_bitflips;
};

class ReplayingHammerer {
 private:
  // the Memory instance for hammering
  Memory &mem;

  // a random number generator, required for std::shuffle
  std::mt19937 gen;

 private:

  // maps: (mapping ID) -> (HammeringPattern), because there's no back-reference from mapping to HammeringPattern
  std::unordered_map<std::string, HammeringPattern> map_mapping_id_to_pattern;

  // the reproducibility score computed during the last invocation of hammer_pattern
  static double last_reproducibility_score;

  // the number of times in which hammering a pattern (at the same location) is repeated; this is only the initial
  // parameter as later we optimize this value
  const int initial_hammering_num_reps = 50;

  // the number of repetitions where we hammer the same pattern at the same location:
  // this is a dynamically learned parameter that is derived from the result of the reproducibility runs; optimizing
  // this allows to save time (and hammer more patterns) as for some DIMMs hammering longer doesn't increase the chance
  // to trigger bit flips
  int hammering_num_reps = initial_hammering_num_reps;

  size_t hammer_pattern(FuzzingParameterSet &fuzz_params, CodeJitter &code_jitter, HammeringPattern &pattern,
                        PatternAddressMapper &mapper, FLUSHING_STRATEGY flushing_strategy,
                        FENCING_STRATEGY fencing_strategy, unsigned long num_reps, int aggressors_for_sync,
                        int num_activations, bool early_stopping, bool sync_each_ref, bool verbose_sync,
                        bool verbose_memcheck, bool verbose_params, bool wait_before_hammering,
                        bool check_flips_after_each_rep);


  std::vector<HammeringPattern> load_patterns_from_json(const std::string& json_filename,
                                                        const std::unordered_set<std::string> &pattern_ids);

  PatternAddressMapper &determine_most_effective_mapping(HammeringPattern &patt,
                                                         bool optimize_hammering_num_reps,
                                                         bool offline_mode);

  [[maybe_unused]] void run_refresh_alignment_experiment(PatternAddressMapper &mapper);

  [[maybe_unused]] void run_code_jitting_probing(PatternAddressMapper &mapper);

  [[maybe_unused]] void find_indirect_effective_aggs(PatternAddressMapper &mapper,
                                    const std::unordered_set<AggressorAccessPattern> &direct_effective_aaps,
                                    std::unordered_set<AggressorAccessPattern> &indirect_effective_aggs);

  [[maybe_unused]] void run_pattern_params_probing(PatternAddressMapper &mapper,
                                  const std::unordered_set<AggressorAccessPattern> &direct_effective_aggs,
                                  std::unordered_set<AggressorAccessPattern> &indirect_effective_aggs);
 public:

  explicit ReplayingHammerer(Memory &mem);

  void set_params(const FuzzingParameterSet &fuzzParams);

  void replay_patterns(const std::string& json_filename, const std::unordered_set<std::string> &pattern_ids);

  size_t replay_patterns_brief(const std::string& json_filename,
                               const std::unordered_set<std::string> &pattern_ids, size_t sweep_bytes,
                               bool running_on_original_dimm);

  size_t replay_patterns_brief(std::vector<HammeringPattern> hammering_patterns, size_t sweep_bytes,
                               size_t num_locations, bool running_on_original_dimm);

  void find_direct_effective_aggs(PatternAddressMapper &mapper,
                                  std::unordered_set<AggressorAccessPattern> &direct_effective_aggs);

  void derive_FuzzingParameterSet_values(HammeringPattern &pattern, PatternAddressMapper &mapper);

  SweepSummary sweep_pattern(HammeringPattern &pattern, PatternAddressMapper &mapper, size_t num_reps,
                             size_t size_bytes);

  SweepSummary sweep_pattern(HammeringPattern &pattern, PatternAddressMapper &mapper, size_t num_reps,
                             size_t size_bytes,
                             const std::unordered_set<AggressorAccessPattern> &effective_aggs);

  static void find_direct_effective_aggs(HammeringPattern &pattern, PatternAddressMapper &mapper,
                                  std::unordered_set<AggressorAccessPattern> &direct_effective_aggs);

// the FuzzingParameterSet instance belonging to the
FuzzingParameterSet params;

  size_t hammer_pattern(FuzzingParameterSet &fuzz_params, CodeJitter &code_jitter, HammeringPattern &pattern,
                        PatternAddressMapper &mapper, FLUSHING_STRATEGY flushing_strategy,
                        FENCING_STRATEGY fencing_strategy, unsigned long num_reps, int aggressors_for_sync,
                        int num_activations, bool early_stopping, bool sync_each_ref, bool verbose_sync,
                        bool verbose_memcheck, bool verbose_params, bool wait_before_hammering,
                        bool check_flips_after_each_rep, std::vector<volatile char *> &hammering_accesses_vec);
};

#endif //BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
