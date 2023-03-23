#include "Memory/DRAMAddr.hpp"


void DRAMAddr::initialize(volatile char *start_address) {
  DRAMAddr::set_base_msb((void *) start_address);
}

void DRAMAddr::set_base_msb(void *buff) {
  base_msb = (size_t) buff & (~((size_t) (1ULL << 30UL) - 1UL));  // get higher order bits above the super page
}

void DRAMAddr::set_config(BlacksmithConfig &config) {
  Config = &config;
  MemConfig = config.to_memconfig();
}

DRAMAddr::DRAMAddr() = default;

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c) {
  bank = bk;
  row = r;
  col = c;
}

DRAMAddr::DRAMAddr(void *addr) {
  auto p = (size_t) addr;
  size_t res = 0;
  for (unsigned long i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(p & i);
  }
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

size_t DRAMAddr::linearize() const {
  return (this->bank << MemConfig.BK_SHIFT) | (this->row << MemConfig.ROW_SHIFT) | (this->col << MemConfig.COL_SHIFT);
}

void *DRAMAddr::to_virt() {
  return const_cast<const DRAMAddr *>(this)->to_virt();
}

void *DRAMAddr::to_virt() const {
  size_t res = 0;
  size_t l = this->linearize();
  for (unsigned long i : MemConfig.ADDR_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(l & i);
  }
  void *v_addr = (void *) (base_msb | res);
  return v_addr;
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  sprintf(buff, "DRAMAddr(b: %zu, r: %zu, c: %zu) = %p",
      this->bank,
      this->row,
      this->col,
      this->to_virt());
  return std::string(buff);
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%ld,%ld,%ld)",
      this->bank,
      this->row,
      this->col);
  return std::string(buff);
}

DRAMAddr DRAMAddr::add(size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return {bank + bank_increment, row + row_increment, col + column_increment};
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  bank += bank_increment;
  row += row_increment;
  col += column_increment;
}

// Define the static DRAM configs
BlacksmithConfig *DRAMAddr::Config;
MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;

#ifdef ENABLE_JSON

nlohmann::json DRAMAddr::get_memcfg_json() {
  nlohmann::json j;
  j["channels"] = Config->channels;
  j["dimms"] = Config->dimms;
  j["ranks"] = Config->ranks;
  j["banks"] = Config->total_banks;
  return j;
}

#endif

uint64_t DRAMAddr::get_row_increment() {
  return MemConfig.DRAM_MTX[1];
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {{"bank", p.bank},
       {"row", p.row},
       {"col", p.col}
  };
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

#endif
