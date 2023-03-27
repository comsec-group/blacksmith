/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef DRAMADDR
#define DRAMADDR

#include <map>
#include <string>
#include <vector>

struct MemConfiguration; // forward declaration needed to break include cycle

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Utilities/BlacksmithConfig.hpp"

#define MTX_SIZE (30U)

struct MemConfiguration {
  size_t BK_SHIFT;
  size_t BK_MASK;
  size_t ROW_SHIFT;
  size_t ROW_MASK;
  size_t COL_SHIFT;
  size_t COL_MASK;
  std::array<size_t, MTX_SIZE> DRAM_MTX;
  std::array<size_t, MTX_SIZE> ADDR_MTX;
};

class DRAMAddr {
 private:
  // Class attributes
  static MemConfiguration MemConfig;
  static BlacksmithConfig *Config;
  static size_t base_msb;

  [[nodiscard]] size_t linearize() const;

 public:
  size_t bank{};
  size_t row{};
  size_t col{};

  // class methods
  static void set_base_msb(void *buff);

  static void set_config(BlacksmithConfig &config);

  // instance methods
  DRAMAddr(size_t bk, size_t r, size_t c);

  explicit DRAMAddr(void *addr);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr();

  void *to_virt();

  [[gnu::unused]] std::string to_string();

  static void initialize(volatile char *start_address);

  [[nodiscard]] std::string to_string_compact() const;

  [[nodiscard]] void *to_virt() const;

  [[nodiscard]] DRAMAddr add(size_t bank_increment, size_t row_increment, size_t column_increment) const;

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);

  static size_t get_bank_count() {
    if (Config == NULL) {
      throw std::logic_error("Config not yet initialized");
    }
    return 1ULL << __builtin_popcountl(MemConfig.BK_MASK);
  }

  static size_t get_row_count() {
    if (Config == NULL) {
      throw std::logic_error("Config not yet initialized");
    }

    size_t row_count = 1ULL << __builtin_popcountl(MemConfig.ROW_MASK);
    return row_count;
  }

#ifdef ENABLE_JSON
  static nlohmann::json get_memcfg_json();
#endif

};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p);

void from_json(const nlohmann::json &j, DRAMAddr &p);

#endif

#endif /* DRAMADDR */
