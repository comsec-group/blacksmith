/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_SRC_FORGES_TRADITIONALHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_TRADITIONALHAMMERER_HPP_

#include "Memory/Memory.hpp"

class TraditionalHammerer {
 private:
  static void hammer_sync(std::vector<volatile char *> &aggressors, size_t reps, int acts, volatile char *d1, volatile char *d2);

 public:
  // do n-sided hammering
  [[maybe_unused]] static void n_sided_hammer(BlacksmithConfig &config, Memory &memory, int acts, long runtime_limit);

  // run experiment where we systematically try out all possible offsets
  [[maybe_unused]] static void n_sided_hammer_experiment(BlacksmithConfig &config, Memory &memory, size_t reps, int acts);

  static void n_sided_hammer_experiment_frequencies(BlacksmithConfig &config, Memory &memory);

  static void hammer(std::vector<volatile char *> &aggressors, size_t reps);

  static void hammer_flush_early(std::vector<volatile char *> &aggressors, size_t reps);
};

#endif //BLACKSMITH_SRC_FORGES_TRADITIONALHAMMERER_HPP_
