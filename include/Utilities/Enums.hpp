/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_
#define BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_

#include <string>
#include <vector>

enum class FLUSHING_STRATEGY : int {
  // flush an accessed aggressor as soon as it has been accessed (i.e., pairs are flushed in-between)
  EARLIEST_POSSIBLE = 1,
  // add the flush right before the next access of the aggressor
  LATEST_POSSIBLE = 2
};

std::string to_string(FLUSHING_STRATEGY strategy);

void from_string(const std::string &strategy, FLUSHING_STRATEGY &dest);

enum class FENCING_STRATEGY : int {
  // do not fence before accessing an aggressor even if it has been accessed before
  OMIT_FENCING = 0,
  // add the fence right after the access
  EARLIEST_POSSIBLE = 1,
  // add the fence right before the next access of the aggressor if it has been flushed before
  LATEST_POSSIBLE = 2,
};

std::string to_string(FENCING_STRATEGY strategy);

void from_string(const std::string &strategy, FENCING_STRATEGY &dest);

std::vector<std::pair<FLUSHING_STRATEGY, FENCING_STRATEGY>> get_valid_strategies();

[[maybe_unused]] std::pair<FLUSHING_STRATEGY, FENCING_STRATEGY> get_valid_strategy_pair();

#endif //BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_
