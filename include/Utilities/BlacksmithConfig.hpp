//
// Created by rowhammer on 27.02.23.
//

#ifndef BLACKSMITH_BLACKSMITHCONFIG_HPP
#define BLACKSMITH_BLACKSMITHCONFIG_HPP

#include <string>
#include <vector>
#include <variant>

typedef std::variant<uint64_t, std::vector<uint64_t>> BitDef;

struct BlacksmithConfig {
    std::string name;
    uint64_t channels;
    uint64_t dimms;
    uint64_t ranks;
    uint64_t total_banks;
    std::vector<BitDef> row_bits;
    std::vector<BitDef> col_bits;
    std::vector<BitDef> dram_bits;
};

bool parse_config(const std::string &filepath, BlacksmithConfig *out);
#endif //BLACKSMITH_BLACKSMITHCONFIG_HPP
