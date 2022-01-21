/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_
#define BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_

#include "Memory/DRAMAddr.hpp"

class BitFlip {
 public:
  // the address where the bit flip was observed
  DRAMAddr address;

  // mask of the bits that flipped, i.e., positions where value == 1 -> flipped bit
  uint8_t bitmask = 0;

  // data containing the bit flips
  uint8_t corrupted_data = 0;

  BitFlip();

  BitFlip(const DRAMAddr &address, uint8_t flips_bitmask, uint8_t corrupted_data);

  [[nodiscard]] size_t count_z2o_corruptions() const;

  [[nodiscard]] size_t count_o2z_corruptions() const;

  [[nodiscard]] size_t count_bit_corruptions() const;

  time_t observation_time;
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const BitFlip &p);

void from_json(const nlohmann::json &j, BitFlip &p);

#endif

#endif //BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_
