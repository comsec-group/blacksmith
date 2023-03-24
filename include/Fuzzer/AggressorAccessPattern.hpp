/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef AGGRESSORACCESSPATTERN
#define AGGRESSORACCESSPATTERN

#include <unordered_map>
#include <utility>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/Aggressor.hpp"

class AggressorAccessPattern {
 public:
  size_t frequency;

  int amplitude;

  size_t start_offset;

  std::vector<Aggressor> aggressors;

  AggressorAccessPattern()
      : frequency(0), amplitude(0), start_offset(0) {};

  AggressorAccessPattern(size_t frequency,
                         int amplitude,
                         std::vector<Aggressor> &aggs,
                         size_t absolute_offset)
      : frequency(frequency),
        amplitude(amplitude),
        start_offset(absolute_offset),
        aggressors(aggs) {
  }

  ~AggressorAccessPattern() = default;

  AggressorAccessPattern(const AggressorAccessPattern &other) = default;

  AggressorAccessPattern& operator=(const AggressorAccessPattern &other);

  [[nodiscard]] std::string to_string() const;
};

bool operator==(const AggressorAccessPattern& lhs, const AggressorAccessPattern& rhs);

// required to use this class with std::unordered_set or any associative container
template<> struct std::hash<AggressorAccessPattern> {
  std::size_t operator()(AggressorAccessPattern const& s) const noexcept {
    std::size_t h1 = std::hash<size_t>{}(s.frequency);
    std::size_t h2 = std::hash<int>{}(s.amplitude);
    std::size_t h3 = std::hash<size_t>{}(s.start_offset);
    std::size_t h4 = std::hash<size_t>{}(s.aggressors.size());
    return h1 ^ (h3 << h2) ^ (h3 << h4);
  }
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const AggressorAccessPattern &p);

void from_json(const nlohmann::json &j, AggressorAccessPattern &p);

#endif

#endif /* AGGRESSORACCESSPATTERN */
