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

// helper type for std::visit
template<class... Ts>
struct overloaded : Ts ... {
  using Ts::operator()...;
};

// explicit deduction guide (not needed as of C++20)
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

BlacksmithConfig::BlacksmithConfig() = default;

BlacksmithConfig BlacksmithConfig::from_jsonfile(const std::string &filepath) {
  std::ifstream is(filepath);
  nlohmann::json j;
  is >> j;
  return j.get<BlacksmithConfig>();
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

MemConfiguration BlacksmithConfig::to_memconfig() {
  MemConfiguration out{};
  size_t i = 0;

  assert(MTX_SIZE == bank_bits.size() + col_bits.size() + row_bits.size());

  out.BK_SHIFT = MTX_SIZE - bank_bits.size();
  out.BK_MASK = (1 << (bank_bits.size())) - 1;
  out.COL_SHIFT = MTX_SIZE - bank_bits.size() - col_bits.size();
  out.COL_MASK = (1 << (col_bits.size())) - 1;
  out.ROW_SHIFT = MTX_SIZE - bank_bits.size() - col_bits.size() - row_bits.size();
  out.ROW_MASK = (1 << (row_bits.size())) - 1;

  // construct dram matrix
  std::array<size_t, MTX_SIZE> dramMtx{};
  auto updateDramMtx = [&i, &dramMtx](const BitDef &def) {
    dramMtx[i++] = bitdef_to_bitstr(def);
  };
  // bank
  std::for_each(bank_bits.begin(), bank_bits.end(), updateDramMtx);
  // col
  std::for_each(col_bits.begin(), col_bits.end(), updateDramMtx);
  // row
  std::for_each(row_bits.begin(), row_bits.end(), updateDramMtx);
  out.DRAM_MTX = dramMtx;

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
  out.ADDR_MTX = addrMtx;
  return out;
}
