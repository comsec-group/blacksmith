/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef HAMMERING_PATTERN
#define HAMMERING_PATTERN

#include <iostream>
#include <random>
#include <unordered_map>
#include <vector>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Utilities/Range.hpp"
#include "Utilities/Uuid.hpp"
#include "PatternAddressMapper.hpp"

class HammeringPattern {
 private:
  static int get_num_digits(size_t x);

 public:
  std::string instance_id;

  // the base period this hammering pattern was generated for
  int base_period;

  size_t max_period;

  int total_activations;

  int num_refresh_intervals;

  // is a pattern is location dependent, then there are some aggressors that are bypassing the mitigation because of
  // their absolute location in DRAM; in this case we need to move only the aggressor pair triggered the bit flips while
  // sweeping the pattern over memory
  bool is_location_dependent;

  // the order in which aggressor accesses happen
  std::vector<Aggressor> aggressors;

  // additional and more structured information about the aggressors involved in this pattern such as whether they are 1-sided or 2-sided
  std::vector<AggressorAccessPattern> agg_access_patterns;

  // from an OOP perspective it would make more sense to have a reference to this HammeringPattern in each of the
  // PatternAddressMapper objects; however, for the JSON export having this vector of mappings for a pattern works
  // better because we need to foreign keys and can easily associate this HammeringPattern to N PatternAddressMappings
  std::vector<PatternAddressMapper> address_mappings;

  HammeringPattern();

  explicit HammeringPattern(int base_period);

  std::string get_pattern_text_repr();

  std::string get_agg_access_pairs_text_repr();

  AggressorAccessPattern &get_access_pattern_by_aggressor(Aggressor &agg);

  PatternAddressMapper &get_most_effective_mapping();

  void remove_mappings_without_bitflips();
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const HammeringPattern &p);

void from_json(const nlohmann::json &j, HammeringPattern &p);

#endif

#endif /* HAMMERING_PATTERN */
