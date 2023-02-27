//
// Created by rowhammer on 27.02.23.
//

#include <fstream>
#include <iostream>
#include "Utilities/BlacksmithConfig.hpp"
#include "nlohmann/json.hpp"
#include "Utilities/Logger.hpp"

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(BlacksmithConfig, name, channels, dimms, ranks, total_banks, row_bits, col_bits,
                                 dram_bits)

bool parse_config(const std::string &filepath, BlacksmithConfig *out) {
  std::ifstream is(filepath);
  nlohmann::json j;
  is >> j;
  *out = j.get<BlacksmithConfig>();
  Logger::log_debug(format_string("Parse config %s", j.dump().c_str()));
  return false;
}

// Try to set the value of type T into the variant data
// if it fails, do nothing
template <typename T, typename... Ts>
void variant_from_json(const nlohmann::json &j, std::variant<Ts...> &data)
{
  try {
    data = j.get<T>();
  } catch (...) {
  }
}

template <typename... Ts>
struct nlohmann::adl_serializer<std::variant<Ts...>>
{
    static void to_json(nlohmann::json &j, const std::variant<Ts...> &data)
    {
      // Will call j = v automatically for the right type
      std::visit(
              [&j](const auto &v) {
                  j = v;
              },
              data);
    }

    static void from_json(const nlohmann::json &j, std::variant<Ts...> &data)
    {
      // Call variant_from_json for all types, only one will succeed
      (variant_from_json<Ts>(j, data), ...);
    }
};