//
// Created by rowhammer on 27.02.23.
//

#include <fstream>
#include <iostream>

#include "Utilities/BlacksmithConfig.hpp"
#include "nlohmann/json.hpp"
#include "Eigen/Core"
#include "Eigen/LU"
#include "Utilities/Logger.hpp"
#include "Memory/DRAMAddr.hpp"

#define BIT_SET(x, b) (x |= 1<<(b))

// (de-)serialize std::variant
template<typename T, typename... Ts>
void variant_from_json(const nlohmann::json &j, std::variant<Ts...> &data) {
  try {
    data = j.get<T>();
  } catch (...) {
  }
}

template<typename... Ts>
struct nlohmann::adl_serializer<std::variant<Ts...>> {
  static void to_json(nlohmann::json &j, const std::variant<Ts...> &data) {
    std::visit([&j](const auto &v) {
      j = v;
    }, data);
  }

  static void from_json(const nlohmann::json &j, std::variant<Ts...> &data) {
    (variant_from_json<Ts>(j, data), ...);
  }
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(BlacksmithConfig, name, channels, dimms, ranks,
                                   total_banks, max_rows, threshold, hammer_rounds, drama_rounds,
                                   memory_size, row_bits, col_bits, bank_bits)

// helper type for std::visit
template<class... Ts>
struct overloaded : Ts ... {
  using Ts::operator()...;
};

// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

bool parse_config(const std::string &filepath, BlacksmithConfig *out) {
  std::ifstream is(filepath);
  nlohmann::json j;
  is >> j;
  *out = j.get<BlacksmithConfig>();
  Logger::log_debug(format_string("Parse config %s", j.dump().c_str()));
  return true;
}

/**
 * Convert a BitDef to the bit string it represents
 * @param def a BitDef
 * @return the bit string represented by `def'
 */
static size_t bitdef_to_bitstr(const BitDef &def) {
  size_t res = 0;
  std::visit(overloaded{
      [&res](const uint64_t &bit) {
        BIT_SET(res, bit);
      },
      [&res](const std::vector<uint64_t> &v) {
        std::for_each(v.begin(), v.end(), [&res](const uint64_t &bit) {
          BIT_SET(res, bit);
        });
      }
  }, def);
  return res;
}

void to_memconfig(const BlacksmithConfig &config, MemConfiguration *out) {
  out->IDENTIFIER = (CHANS(config.channels) | DIMMS(config.dimms) | RANKS(config.ranks) | BANKS(config.total_banks));
  size_t i = 0;

  assert(MTX_SIZE == config.bank_bits.size() + config.col_bits.size() + config.row_bits.size());

  out->BK_SHIFT = MTX_SIZE - config.bank_bits.size();
  out->BK_MASK = (1 << (config.bank_bits.size())) - 1;
  out->COL_SHIFT = MTX_SIZE - config.bank_bits.size() - config.col_bits.size();
  out->COL_MASK = (1 << (config.col_bits.size())) - 1;
  out->ROW_SHIFT = MTX_SIZE - config.bank_bits.size() - config.col_bits.size() - config.row_bits.size();
  out->ROW_MASK = (1 << (config.row_bits.size())) - 1;

  // construct dram matrix
  std::array<size_t, MTX_SIZE> dramMtx{};
  auto updateDramMtx = [&i, &dramMtx](const BitDef &def) {
    dramMtx[i++] = bitdef_to_bitstr(def);
  };
  // bank
  std::for_each(config.bank_bits.begin(), config.bank_bits.end(), updateDramMtx);
  // col
  std::for_each(config.col_bits.begin(), config.col_bits.end(), updateDramMtx);
  // row
  std::for_each(config.row_bits.begin(), config.row_bits.end(), updateDramMtx);
  out->DRAM_MTX = dramMtx;

  // construct addr matrix
  std::array<size_t, MTX_SIZE> addrMtx{};
  // create dram matrix in eigen
  Eigen::Matrix<bool, MTX_SIZE, MTX_SIZE> matrix(MTX_SIZE, MTX_SIZE);
  for (long row = 0; row < MTX_SIZE; ++row) {
    for (long col = 0; col < MTX_SIZE; ++col) {
      matrix(row, col) = (dramMtx[row] >> (MTX_SIZE - col - 1)) & 1;
    }
  }
  // invert dram matrix, assign addr matrix
  Eigen::FullPivLU<Eigen::Matrix<double, MTX_SIZE, MTX_SIZE>> matrixDecomp(matrix.cast<double>());
  if(!matrixDecomp.isInvertible()) {
    Logger::log_error("The matrix defined in the config file is not invertible.");
    exit(EXIT_FAILURE);
  }
  matrix = matrixDecomp.inverse().cast<bool>();
  for (long row = 0; row < MTX_SIZE; ++row) {
    for (long col = 0; col < MTX_SIZE; ++col) {
      addrMtx[row] |= matrix(row, col) << (MTX_SIZE - col - 1);
    }
  }
  out->ADDR_MTX = addrMtx;
}
