/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef RANGE
#define RANGE

#include <random>
#include "Logger.hpp"

template<typename T = int>
struct Range {
  T min{0};

  T max{0};

  T step{1};

  std::uniform_int_distribution<T> dist;

  Range() = default;

  Range(T min, T max) : min(min), max(max), dist(std::uniform_int_distribution<T>(min, max)) {}

  Range(T min, T max, T step) : min(min), max(max), step(step) {
    if (min%step!=0 || max%step!=0) {
      Logger::log_error(
          format_string("Range(%d,%d,%d) failed: min and max must both be divisible by step.", min, max, step));
      exit(1);
    }
    dist = std::uniform_int_distribution<T>(min/step, max/step);
  }

  T get_random_number(std::mt19937 &gen) {
    if (min==max) {
      return min;
    } else if (max < min) {
      std::swap(max, min);
    }
    auto number = dist(gen);
    return (step!=1) ? number*step : number;
  }

  T get_random_number(int upper_bound, std::mt19937 &gen) {
    T number;
    if (max > upper_bound) {
      number = Range(min, upper_bound).get_random_number(gen);
    } else {
      number = dist(gen);
    }
    return (step!=1) ? number*step : number;
  }
};
#endif /* RANGE */
