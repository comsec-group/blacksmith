#include "Memory/DramAnalyzer.hpp"

#include <cassert>
#include <unordered_set>

DramAnalyzer::DramAnalyzer(volatile char *target, BlacksmithConfig &config) :
  config(config), start_address(target) {}

size_t DramAnalyzer::count_acts_per_ref() {
  // collect bitmask for all bank fns, set ``a'' to first address in allocated mem
  size_t bank_mask = bitdef_to_bitstr(config.bank_bits.at(0));
  volatile char *a = start_address;
  size_t a_bank_mask = ((size_t)a) & bank_mask;
  size_t row_mask = bitdef_to_bitstr(config.row_bits.at(0));
  size_t a_row_mask = ((size_t)a) & row_mask;
  // starting with a+1, find different row address b on the same bank as a
  volatile char *b;
  for (b = a+1; (((size_t)b) & bank_mask) != a_bank_mask || (((size_t)b) & row_mask) == a_row_mask; ++b);

  Logger::log_debug(format_string("We will use %p and %p for count_acts_per_ref", a, b));

  size_t skip_first_N = 50;
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before, after;
  uint64_t activation_count = 0, activation_count_old = 0;

  // bring a and b into the cache
  (void)*a;
  (void)*b;

  // computes the standard deviation
  auto compute_std = [](
      std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
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

    activation_count += 2;

    if ((after - before) > 1000) {  // hard coded magic no?
      if (i > skip_first_N && activation_count_old != 0) {
        uint64_t value = (activation_count - activation_count_old) * 2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 1 -> then stop collecting measurements
        if ((acts.size()%200)==0 && compute_std(acts, running_sum, acts.size())<3.0)
          break;
        if ((acts.size()%1000000)==0) {
          Logger::log_info(format_string("Failed to fix standard derivation (%f) after 1000000 rounds. Retrying", compute_std(acts, running_sum, acts.size())));
          acts.clear();
          running_sum = 0;
          i = 0;
          activation_count = 0;
        }
      }
      activation_count_old = activation_count;
    }
  }

  auto activations = (running_sum/acts.size());
  Logger::log_info(format_string("Determined the number of possible ACTs per refresh interval after %d rounds.", acts.size()));
  Logger::log_data(format_string("num_acts_per_tREFI: %lu", activations));

  return activations;
}
