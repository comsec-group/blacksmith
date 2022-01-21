/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_SRC_MEMORY_H_
#define BLACKSMITH_SRC_MEMORY_H_

#include <cstdint>
#include <cstdlib>
#include <string>

#include "Memory/DramAnalyzer.hpp"
#include "Fuzzer/PatternAddressMapper.hpp"

enum class DATA_PATTERN : char {
  ZEROES, ONES, RANDOM
};

class Memory {
 private:
  /// the starting address of the allocated memory area
  /// this is a fixed value as the assumption is that all memory cells are equally vulnerable
  volatile char *start_address = (volatile char *) 0x2000000000;

  // the mount point of the huge pages filesystem
  const std::string hugetlbfs_mountpoint = "/mnt/huge/buff";

  // the size of the allocated memory area in bytes
  uint64_t size;

  // whether this memory allocation is backed up by a superage
  const bool superpage;

  size_t check_memory_internal(PatternAddressMapper &mapping, const volatile char *start,
                               const volatile char *end, bool reproducibility_mode, bool verbose);

 public:

  // the flipped bits detected during the last call to check_memory
  std::vector<BitFlip> flipped_bits;

  explicit Memory(bool use_superpage);

  ~Memory();

  void allocate_memory(size_t mem_size);

  void initialize(DATA_PATTERN data_pattern);

  size_t check_memory(const volatile char *start, const volatile char *end);

  size_t check_memory(PatternAddressMapper &mapping, bool reproducibility_mode, bool verbose);

  [[nodiscard]] volatile char *get_starting_address() const;

  std::string get_flipped_rows_text_repr();
};

#endif //BLACKSMITH_SRC_MEMORY_H_
