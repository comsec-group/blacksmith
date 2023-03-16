//
// Created by rowhammer on 27.02.23.
//

#ifndef BLACKSMITH_BLACKSMITHCONFIG_HPP
#define BLACKSMITH_BLACKSMITHCONFIG_HPP

#include <string>
#include <vector>
#include <variant>
#include "Memory/DRAMAddr.hpp"

typedef std::variant<uint64_t, std::vector<uint64_t>> BitDef;

struct BlacksmithConfig {
    std::string name;
    uint64_t channels;
    uint64_t dimms;
    uint64_t ranks;
    uint64_t total_banks;
    uint64_t max_rows;  // maximum number of aggressor rows
    uint8_t threshold;  // threshold to distinguish between cache miss (t > THRESH) and cache hit (t < THRESH)
    uint64_t memory_size;
    std::vector<BitDef> row_bits;
    std::vector<BitDef> col_bits;
    std::vector<BitDef> bank_bits;
};

/**
 * Parse a config file into a BlacksmithConfig
 *
 * @param filepath path to a JSON config file
 * @param out a pointer to a BlacksmithConfig. `out' will be populated according to the contents of `filepath',
 * @return true iff deserialization succeeded, false otherwise
 */
bool parse_config(const std::string &filepath, BlacksmithConfig *out);

/**
 * Convert a BlacksmithConfig to a MemConfiguration for use in DRAMAddr.
 *
 * @param config a reference to a BlacksmithConfig
 * @param out a pointer to a MemConfiguration. `out' will be updated with bit definitions from BlacksmithConfig
 */
void to_memconfig(const BlacksmithConfig &config, MemConfiguration *out);
#endif //BLACKSMITH_BLACKSMITHCONFIG_HPP
