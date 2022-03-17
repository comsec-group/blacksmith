#include "Memory/DramAnalyzer.hpp"

#include <cassert>
#include <unordered_set>

DramAnalyzer::DramAnalyzer(BlacksmithConfig &config, volatile char *target) :
  config(config), start_address(target) {
  std::random_device rd;
  gen = std::mt19937(rd());
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
}

size_t DramAnalyzer::count_acts_per_trefi() {
  const int ROW_LENGTH = 64;
  DRAMAddr a((void*)start_address);
  DRAMAddr b;
  bool did_find_same_bank_diff_rows = false;
  for (size_t offset = 0; !did_find_same_bank_diff_rows && offset < config.memory_size; offset += ROW_LENGTH) {
    b = DRAMAddr((void*)(start_address + offset));
    did_find_same_bank_diff_rows = a.bank == b.bank && a.row != b.row;
  }
  if(!did_find_same_bank_diff_rows) {
    Logger::log_error("Failed to find two differing-row addresses on the same bank. Is your config correct?");
    exit(1);
  }
  Logger::log_debug(format_string("We will use %p and %p for count_acts_per_ref", a.to_virt(), b.to_virt()));

  return count_acts_per_trefi((volatile char*)a.to_virt(),(volatile char*)b.to_virt());
}

size_t DramAnalyzer::count_acts_per_trefi(volatile char *a, volatile char *b) {
  size_t skip_first_N = 50;
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before;
  uint64_t after;
  uint64_t count = 0;
  uint64_t count_old = 0;

  // computes the standard deviation
  auto compute_std = [](std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
    double mean = static_cast<double>(running_sum)/static_cast<double>(num_numbers);
    double var = 0;
    for (const auto &num : values) {
      if (static_cast<double>(num) < mean) continue;
      var += std::pow(static_cast<double>(num) - mean, 2);
    }
    auto val = std::sqrt(var/static_cast<double>(num_numbers));
    return val;
  };

  for (size_t i = 0;; i++) {
    // flush a and b from caches
    clflushopt(a);
    clflushopt(b);
    mfence();

    // get start timestamp and wait until we retrieved it
    before = rdtscp();
    lfence();

    // do DRAM accesses
    (void)*a;
    (void)*b;

    // get end timestamp
    after = rdtscp();

    count++;
    if ((after - before) > 1000) {
      if (i > skip_first_N && count_old!=0) {
        // multiply by 2 to account for both accesses we do (a, b)
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 1 -> then stop collecting measurements
        if ((acts.size()%200)==0 && compute_std(acts, running_sum, acts.size())<3.0) break;
      }
      count_old = count;
    }
  }

  auto activations = (running_sum/acts.size());
  Logger::log_info(format_string("Determined the number of possible ACTs per refresh interval after %d rounds.", acts.size()));
  Logger::log_data(format_string("num_acts_per_tREFI: %lu", activations));

  return activations;
}

std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> DramAnalyzer::measure_timings(size_t sample_size) {
  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> result;
  for( size_t sampleIdx = 0; sampleIdx < sample_size; sampleIdx++) {
    auto a1 = start_address + (dist(gen)%(config.memory_size/64))*64;
    auto a2 = start_address + (dist(gen)%(config.memory_size/64))*64;
    auto timing = measure_time(a1, a2, config.drama_rounds);
    result.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1),reinterpret_cast<std::uintptr_t>(a2),timing ));
  }
  return result;
}
