#include "Fuzzer/BitFlip.hpp"

#include <bitset>

#ifdef ENABLE_JSON

#include <sstream>
#include <unistd.h>

void to_json(nlohmann::json &j, const BitFlip &p) {
  std::stringstream addr;
  addr << "0x" << std::hex << (uint64_t)p.address.to_virt();
  j = nlohmann::json{{"dram_addr", p.address},
                     {"bitmask", p.bitmask},
                     {"data", p.corrupted_data},
                     {"observed_at", p.observation_time},
                     {"addr", addr.str()},
                     {"page_offset", (uint64_t)p.address.to_virt()%getpagesize()}
  };
}

void from_json(const nlohmann::json &j, BitFlip &p) {
  j.at("dram_addr").get_to(p.address);
  j.at("bitmask").get_to(p.bitmask);
  j.at("data").get_to(p.corrupted_data);
  // to preserve backward-compatibility
  if (j.contains("observed_at")) {
    j.at("observed_at").get_to(p.observation_time);
  } else {
    p.observation_time = 0;
  }
}

#endif

BitFlip::BitFlip(const DRAMAddr &address, uint8_t flips_bitmask, uint8_t corrupted_data)
    : address(address), bitmask(flips_bitmask), corrupted_data(corrupted_data) {
  observation_time = time(nullptr);
}

BitFlip::BitFlip() {
  observation_time = time(nullptr);
}

size_t BitFlip::count_z2o_corruptions() const {
  const auto bitmask_nbits = sizeof(bitmask)*8;
  std::bitset<bitmask_nbits> mask_bits(bitmask);
  const auto data_nbits = sizeof(corrupted_data)*8;
  std::bitset<data_nbits> data_bits(corrupted_data);
  // we assume that both (corrupted_data, bitmask) have the same no. of bits
  size_t z2o_corruptions = 0;
  for (size_t i = 0; i < mask_bits.size(); ++i) {
    if (mask_bits[i]==1 && data_bits[i]==1)
      z2o_corruptions++;
  }
  return z2o_corruptions;
}

size_t BitFlip::count_o2z_corruptions() const {
  const auto bitmask_nbits = sizeof(bitmask)*8;
  std::bitset<bitmask_nbits> mask_bits(bitmask);
  const auto data_nbits = sizeof(corrupted_data)*8;
  std::bitset<data_nbits> data_bits(corrupted_data);
  // we assume that both (corrupted_data, bitmask) have the same no. of bits
  size_t o2z_corruptions = 0;
  for (size_t i = 0; i < mask_bits.size(); ++i) {
    if (mask_bits[i]==1 && data_bits[i]==0)
      o2z_corruptions++;
  }
  return o2z_corruptions;
}

size_t BitFlip::count_bit_corruptions() const {
  auto n = bitmask;
  unsigned int count = 0;
  // based on Brian Kernighan's algorithm (https://www.geeksforgeeks.org/count-set-bits-in-an-integer/) that counts the
  // number of set bits of an integer in O(log n)
  while (n > 0) {
    n &= (n - 1);
    count++;
  }
  return count;
}
