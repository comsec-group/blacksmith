#include "Forges/TraditionalHammerer.hpp"

#include "Utilities/TimeHelper.hpp"
#include "Blacksmith.hpp"

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void TraditionalHammerer::hammer(std::vector<volatile char *> &aggressors) {
  hammer(aggressors, HAMMER_ROUNDS);
}

void TraditionalHammerer::hammer(std::vector<volatile char *> &aggressors, size_t reps) {
  for (size_t i = 0; i < reps; i++) {
    for (auto &a : aggressors) {
      (void)*a;
    }
    for (auto &a : aggressors) {
      clflushopt(a);
    }
    mfence();
  }
}

void TraditionalHammerer::hammer_flush_early(std::vector<volatile char *> &aggressors, size_t reps) {
  for (size_t i = 0; i < reps; i++) {
    for (auto &a : aggressors) {
      (void)*a;
      clflushopt(a);
    }
    mfence();
  }
}

/// Performs synchronized hammering on the given aggressor rows.
void TraditionalHammerer::hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                                      volatile char *d1, volatile char *d2) {
  size_t ref_rounds = std::max(1UL, acts/aggressors.size());

  // determines how often we are repeating
  size_t agg_rounds = ref_rounds;
  uint64_t before, after;

  (void)*d1;
  (void)*d2;

  // synchronize with the beginning of an interval
  while (true) {
    clflushopt(d1);
    clflushopt(d2);
    mfence();
    before = rdtscp();
    lfence();
    (void)*d1;
    (void)*d2;
    after = rdtscp();
    // check if an ACTIVATE was issued
    if ((after - before) > 1000) {
      break;
    }
  }

  // perform hammering for HAMMER_ROUNDS/ref_rounds times
  for (size_t i = 0; i < HAMMER_ROUNDS/ref_rounds; i++) {
    for (size_t j = 0; j < agg_rounds; j++) {
      for (size_t k = 0; k < aggressors.size() - 2; k++) {
        (void)(*aggressors[k]);
        clflushopt(aggressors[k]);
      }
      mfence();
    }

    // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
    while (true) {
      mfence();
      lfence();
      before = rdtscp();
      lfence();
      clflushopt(d1);
      (void)*d1;
      clflushopt(d2);
      (void)*d2;
      after = rdtscp();
      lfence();
      // stop if an ACTIVATE was issued
      if ((after - before) > 1000) break;
    }
  }
}

[[maybe_unused]] void TraditionalHammerer::n_sided_hammer_experiment(Memory &memory, int acts) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dist(0, std::numeric_limits<size_t>::max());

  // This implement the experiment showing the offset is an important factor when crafting patterns.
  // Randomly chooses a double-sided pair
  // Create a pattern of N ACTIVATEs (determine based on number of ACTs per tREF)
  // Loop over the offset (position of double-sided pair within pattern)
  // Place aggressors at current offset and randomize all other accesses
  // Hammer pattern for acts activations
  // Scan for flipped rows

#ifdef ENABLE_JSON
  nlohmann::json all_results = nlohmann::json::array();
  nlohmann::json current;
#endif

  const auto start_ts = time(nullptr);
  const auto num_aggs = 2;
  const auto pattern_length = (size_t) acts;

  size_t v = 2;  // distance between aggressors (within a pair)

  size_t low_row_no;
  void *low_row_vaddr;
  size_t high_row_no;
  void *high_row_vaddr;

  auto update_low_high = [&](DRAMAddr &dramAddr) {
    if (dramAddr.row < low_row_no) {
      low_row_no = dramAddr.row;
      low_row_vaddr = dramAddr.to_virt();
    }
    if (dramAddr.row > high_row_no) {
      high_row_no = dramAddr.row;
      high_row_vaddr = dramAddr.to_virt();
    }
  };

  const auto TARGET_BANK = 0;
  const auto NUM_LOCATIONS = 10;
  const size_t MAX_AMPLITUDE = 6;

  for (size_t cur_location = 1; cur_location <= NUM_LOCATIONS; ++cur_location) {
    // start address/row
    DRAMAddr cur_next_addr(TARGET_BANK, dist(gen)%2048, 0);

    for (size_t cur_amplitude = 1; cur_amplitude <= MAX_AMPLITUDE; ++cur_amplitude) {

      for (size_t cur_offset = 75; cur_offset < pattern_length - (num_aggs - 1); ++cur_offset) {

        Logger::log_debug(format_string("Running: cur_offset = %lu, cur_amplitude = %lu, cur_location = %lu/%lu",
            cur_offset, cur_amplitude, cur_location, NUM_LOCATIONS));

        low_row_no = std::numeric_limits<size_t>::max();
        low_row_vaddr = nullptr;
        high_row_no = std::numeric_limits<size_t>::min();
        high_row_vaddr = nullptr;

        std::vector<volatile char *> aggressors;
        std::stringstream ss;

        // fill up the pattern with accesses
        ss << "agg row: ";
        for (size_t pos = 0; pos < pattern_length;) {
          if (pos==cur_offset) {
            // add the aggressor pair
            DRAMAddr agg1 = cur_next_addr;
            DRAMAddr agg2 = agg1.add(0, v, 0);
            ss << agg1.row << " ";
            ss << agg2.row << " ";
            update_low_high(agg1);
            update_low_high(agg2);
            for (size_t cnt = cur_amplitude; cnt > 0; --cnt) {
              aggressors.push_back((volatile char *) agg1.to_virt());
              aggressors.push_back((volatile char *) agg2.to_virt());
              pos += 2;
            }
          } else {
            // fill up the remaining accesses with random rows
            DRAMAddr agg(TARGET_BANK, dist(gen)%1024, 0);
//          update_low_high(agg);
            ss << agg.row << " ";
            aggressors.push_back((volatile char *) agg.to_virt());
            pos++;
          }
        }
        Logger::log_data(ss.str());
        Logger::log_debug(format_string("#aggs in pattern = %lu", aggressors.size()));

        // do the hammering
        if (!program_args.use_synchronization) {
          // CONVENTIONAL HAMMERING
          Logger::log_info(format_string("Hammering %d aggressors on bank %d", num_aggs, TARGET_BANK));
          hammer(aggressors);
        } else if (program_args.use_synchronization) {
          // SYNCHRONIZED HAMMERING
          // uses one dummy that are hammered repeatedly until the refresh is detected
          cur_next_addr.add_inplace(0, 100, 0);
          auto d1 = cur_next_addr;
          cur_next_addr.add_inplace(0, 2, 0);
          auto d2 = cur_next_addr;
          Logger::log_info(
              format_string("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
                  d1.row, d1.to_virt(),
                  d2.row, d2.to_virt()));

          Logger::log_info(format_string("Hammering sync %d aggressors on bank %d", num_aggs, TARGET_BANK));
          hammer_sync(aggressors, acts, (volatile char *) d1.to_virt(), (volatile char *) d2.to_virt());
        }

        // check 20 rows before and after the placed aggressors for flipped bits
        Logger::log_debug("Checking for flipped bits...");
        const auto check_rows_around = 20;
        auto num_bitflips = memory.check_memory((volatile char *) low_row_vaddr, (volatile char *) high_row_vaddr);
#ifdef ENABLE_JSON
        current["cur_offset"] = cur_offset;
        current["cur_amplitude"] = cur_amplitude;
        current["location"] = cur_location;
        current["num_bitflips"] = num_bitflips;
        current["pattern_length"] = pattern_length;
        current["check_rows_around"] = check_rows_around;

        current["aggressors"] = nlohmann::json::array();
        nlohmann::json agg_1;
        DRAMAddr d((void *) aggressors[cur_offset]);
        agg_1["bank"] = d.bank;
        agg_1["row"] = d.row;
        agg_1["col"] = d.col;
        current["aggressors"].push_back(agg_1);
        nlohmann::json agg_2;
        DRAMAddr d2((void *) aggressors[cur_offset + 1]);
        agg_2["bank"] = d2.bank;
        agg_2["row"] = d2.row;
        agg_2["col"] = d2.col;
        current["aggressors"].push_back(agg_2);

        all_results.push_back(current);
#endif
      }
    }
  }

#ifdef ENABLE_JSON
// export result into JSON
  std::ofstream json_export("experiment-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;
  meta["acts_per_tref"] = acts;
  meta["seed"] = start_ts;

  nlohmann::json root;
  root["metadata"] = meta;
  root["results"] = all_results;

  json_export << root << std::endl;
  json_export.close();
#endif
}

[[maybe_unused]] void TraditionalHammerer::n_sided_hammer(Memory &memory, int acts, long runtime_limit) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dist(0, std::numeric_limits<size_t>::max());

  const auto execution_limit = get_timestamp_sec() + runtime_limit;
  while (get_timestamp_sec() < execution_limit) {
    size_t aggressor_rows_size = (dist(gen)%(MAX_ROWS - 3)) + 3;  // number of aggressor rows
    size_t v = 2;  // distance between aggressors (within a pair)
    size_t d = dist(gen)%16;  // distance of each double-sided aggressor pair

    for (size_t ba = 0; ba < 4; ba++) {
      DRAMAddr cur_next_addr(ba, dist(gen)%4096, 0);

      std::vector<volatile char *> aggressors;
      std::stringstream ss;

      ss << "agg row: ";
      for (size_t i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr.add_inplace(0, d, 0);
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());

        cur_next_addr.add_inplace(0, v, 0);
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());
      }

      if ((aggressor_rows_size%2)!=0) {
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());
      }
      Logger::log_data(ss.str());

      if (!program_args.use_synchronization) {
        // CONVENTIONAL HAMMERING
        Logger::log_info(format_string("Hammering %d aggressors with v=%d d=%d on bank %d",
            aggressor_rows_size, v, d, ba));
        hammer(aggressors);
      } else if (program_args.use_synchronization) {
        // SYNCHRONIZED HAMMERING
        // uses two dummies that are hammered repeatedly until the refresh is detected
        cur_next_addr.add_inplace(0, 100, 0);
        auto d1 = cur_next_addr;
        cur_next_addr.add_inplace(0, v, 0);
        auto d2 = cur_next_addr;
        Logger::log_info(format_string("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
            d1.row, d1.to_virt(), d2.row, d2.to_virt()));
        if (ba==0) {
          Logger::log_info(format_string("sync: ref_rounds %lu, remainder %lu.", acts/aggressors.size(),
              acts - ((acts/aggressors.size())*aggressors.size())));
        }
        Logger::log_info(format_string("Hammering sync %d aggressors on bank %d", aggressor_rows_size, ba));
        hammer_sync(aggressors, acts, (volatile char *) d1.to_virt(), (volatile char *) d2.to_virt());
      }

      // check 100 rows before and after for flipped bits
      memory.check_memory(aggressors[0], aggressors[aggressors.size() - 1]);
    }
  }
}

void TraditionalHammerer::n_sided_hammer_experiment_frequencies(Memory &memory) {
#ifdef ENABLE_JSON
  nlohmann::json root;
  nlohmann::json all_results = nlohmann::json::array();
  nlohmann::json current;
#endif
  const auto start_ts = get_timestamp_sec();

  std::random_device rd;
  std::mt19937 gen(rd());

  const auto MAX_AGG_ROUNDS = 48; //16;  // 1...MAX_AGG_ROUNDS
  const auto MIN_AGG_ROUNDS = 32; //16;  // 1...MAX_AGG_ROUNDS

  const auto MAX_DMY_ROUNDS = 256; // 64;     // 0...MAX_DMY_ROUNDS
  const auto MIN_DMY_ROUNDS = 110; // 64;     // 0...MAX_DMY_ROUNDS

  const auto MAX_ROW = 4096;

//  auto agg1 = DRAMAddr(11, 5307, 0);
//  auto agg2 = DRAMAddr(11, 5309, 0);

//  auto agg1 = DRAMAddr(3, 3835, 0);
//  auto agg2 = DRAMAddr(3, 3837, 0);
//
//  auto agg1 = DRAMAddr(15, 3778, 0);
//  auto agg2 = DRAMAddr(15, 3780, 0);

//  auto agg1 = DRAMAddr(14, 5729, 0);
//  auto agg2 = DRAMAddr(14, 5731, 0);


#ifdef ENABLE_JSON

#endif

  // randomly choose two dummies
//  auto dmy1 = DRAMAddr(agg1.bank, agg1.row + rand()%(MAX_ROW - agg1.row), 0);
//  auto dmy2 = DRAMAddr(agg1.bank, dmy1.row + 2, 0);

//  auto dmy1 = DRAMAddr(10, 408, 0);
//  auto dmy2 = DRAMAddr(10, 410, 0);

//#ifdef ENABLE_JSON
//  root["dummies"] = nlohmann::json::array();
//  for (const auto dmy: {dmy1, dmy2}) {
//    root["dummies"].push_back({{"bank", dmy.bank}, {"row", dmy.row}, {"col", dmy.col}});
//  }
//#endif

//  Logger::log_debug(format_string("agg rows: r%lu, r%lu", agg1.row, agg2.row));
//  Logger::log_debug(format_string("dmy rows: r%lu, r%lu", dmy1.row, dmy2.row));





//  std::shuffle(untested_vals.begin(), untested_vals.end(), gen);
for (size_t r = 0; r < 10; ++ r) {

  // randomly choose two aggressors
  auto agg1 = DRAMAddr(
      Range<size_t>(0, NUM_BANKS-1).get_random_number(gen),
      Range<size_t>(0, MAX_ROW-1).get_random_number(gen),
      0);
  auto agg2 = DRAMAddr(agg1.bank, agg1.row + 2, 0);

  std::vector<std::tuple<size_t, size_t>> untested_vals;
  for (size_t agg_rounds = MIN_AGG_ROUNDS; agg_rounds < MAX_AGG_ROUNDS; ++agg_rounds) {
    for (size_t dummy_rounds = MIN_DMY_ROUNDS; dummy_rounds < MAX_DMY_ROUNDS; ++dummy_rounds) {
      untested_vals.emplace_back(agg_rounds, dummy_rounds);
    }
  }

  for (size_t i = 0; i < untested_vals.size(); ++i) {
    std::vector<volatile char *> aggressors;

//    auto agg1 = DRAMAddr(Range<size_t>(0, NUM_BANKS).get_random_number(gen),
//        Range<size_t>(0, MAX_ROW).get_random_number(gen),
//        0);
//    auto agg2 = agg1.add(0, 2, 0);
    auto dmy1 = DRAMAddr(agg1.bank,
        Range<size_t>(0, MAX_ROW).get_random_number(gen),
        0);
    auto dmy2 = dmy1.add(0, 2, 0);
    Logger::log_debug(format_string("aggs [%s, %s], dmys [%s, %s]",
        agg1.to_string_compact().c_str(), agg2.to_string_compact().c_str(),
        dmy1.to_string_compact().c_str(), dmy2.to_string_compact().c_str()));

    const auto tuple_vals = untested_vals.at(i);
    size_t agg_rounds = std::get<0>(tuple_vals);
    size_t dummy_rounds = std::get<1>(tuple_vals);

    Logger::log_debug(format_string("Running: location = %lu/10, agg_rounds = %lu, dummy_rounds = %lu. Remaining: %lu.",
        r+1,
        agg_rounds,
        dummy_rounds,
        untested_vals.size() - i));

    for (size_t ard = 0; ard < agg_rounds; ++ard) {
      aggressors.push_back((volatile char *) agg1.to_virt());
      aggressors.push_back((volatile char *) agg2.to_virt());
    }

    for (size_t drd = 0; drd < dummy_rounds; ++drd) {
//      aggressors.push_back((volatile char *) dmy1.to_virt());
//      aggressors.push_back((volatile char *) dmy2.to_virt());
      auto dmy = DRAMAddr(Range<size_t>(0, NUM_BANKS - 1).get_random_number(gen),
          Range<size_t>(0, MAX_ROW - 1).get_random_number(gen),
          0);
      aggressors.push_back((volatile char *) dmy.to_virt());
    }

    // hammer the pattern
    Logger::log_info("Hammering...");
    hammer_flush_early(aggressors, 8192*32);
//    hammer(aggressors, 5000000/aggressors.size());
//    hammer(aggressors, 8192*32);
//    hammer_sync(aggressors, program_args.acts_per_trefi,
//        (volatile char *) dmy2.add(0, 111, 0).to_virt(),
//        (volatile char *) dmy2.add(0, 113, 0).to_virt());

    // check rows before and after for flipped bits
    const auto check_rows_around = 15;
    Logger::log_info("Checking for flipped bits...");
    auto sum_bitflips = memory.check_memory((volatile char *) agg1.to_virt(),
        (volatile char *) agg1.add(0, 1, 0).to_virt());
//    sum_bitflips += memory.check_memory((volatile char *) agg2.to_virt(),
//        (volatile char *) agg2.add(0, 1, 0).to_virt(),
//        check_rows_around);
//    sum_bitflips += memory.check_memory((volatile char *) dmy1.to_virt(),
//        (volatile char *) dmy1.add(0, 1, 0).to_virt(),
//        check_rows_around);
//    sum_bitflips += memory.check_memory((volatile char *) dmy2.to_virt(),
//        (volatile char *) dmy2.add(0, 1, 0).to_virt(),
//        check_rows_around);

    // log results into JSON
#ifdef ENABLE_JSON
    current["aggressors"] = nlohmann::json::array();
    for (const auto agg: {agg1, agg2}) {
      current["aggressors"].push_back({{"bank", agg.bank}, {"row", agg.row}, {"col", agg.col}});
    }
    current["agg_rounds"] = agg_rounds;
    current["dummy_rounds"] = dummy_rounds;
    current["num_bitflips"] = sum_bitflips;
    current["pattern_length"] = aggressors.size();
    current["check_rows_around"] = check_rows_around;

    all_results.push_back(current);
#endif
//    }
//  }
  }
}
  // write JSON to disk
#ifdef ENABLE_JSON
  // export result into JSON
  std::ofstream json_export("experiment-vendorC-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;
  meta["seed"] = start_ts;

  root["metadata"] = meta;
  root["results"] = all_results;

  json_export << root << std::endl;
  json_export.close();
#endif
}
