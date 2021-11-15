#include "Fuzzer/CodeJitter.hpp"

CodeJitter::CodeJitter()
    : pattern_sync_each_ref(false),
      flushing_strategy(FLUSHING_STRATEGY::EARLIEST_POSSIBLE),
      fencing_strategy(FENCING_STRATEGY::LATEST_POSSIBLE),
      total_activations(5000000),
      num_aggs_for_sync(2) {
#ifdef ENABLE_JITTING
  logger = new asmjit::StringLogger;
#endif
}

CodeJitter::~CodeJitter() {
  cleanup();
}

void CodeJitter::cleanup() {
#ifdef ENABLE_JITTING
  if (fn!=nullptr) {
    runtime.release(fn);
    fn = nullptr;
  }
  if (logger!=nullptr) {
    delete logger;
    logger = nullptr;
  }
#endif
}

int CodeJitter::hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose) {
  if (fn==nullptr) {
    Logger::log_error("Skipping hammering pattern as pattern could not be created successfully.");
    return -1;
  }
  if (verbose) Logger::log_info("Hammering the last generated pattern.");
  int total_sync_acts = fn();

  if (verbose) {
    Logger::log_info("Synchronization stats:");
    Logger::log_data(format_string("Total sync acts: %d", total_sync_acts));

    const auto total_acts_pattern = fuzzing_parameters.get_total_acts_pattern();
    auto pattern_rounds = fuzzing_parameters.get_hammering_total_num_activations()/total_acts_pattern;
    auto acts_per_pattern_round = pattern_sync_each_ref
                                  // sync after each num_acts_per_tREFI: computes how many activations are necessary
                                  // by taking our pattern's length into account
                                  ? (total_acts_pattern/fuzzing_parameters.get_num_activations_per_t_refi())
                                  // beginning and end of pattern; for simplicity we only consider the end of the
                                  // pattern here (=1) as this is the sync that is repeated after each hammering run
                                  : 1;
    auto num_synced_refs = pattern_rounds*acts_per_pattern_round;
    Logger::log_data(format_string("Number of pattern reps while hammering: %d", pattern_rounds));
    Logger::log_data(format_string("Number of total synced REFs (est.): %d", num_synced_refs));
    Logger::log_data(format_string("Avg. number of acts per sync: %d", total_sync_acts/num_synced_refs));
  }

  return total_sync_acts;
}

void CodeJitter::jit_strict(int num_acts_per_trefi,
                            FLUSHING_STRATEGY flushing,
                            FENCING_STRATEGY fencing,
                            const std::vector<volatile char *> &aggressor_pairs,
                            bool sync_each_ref,
                            int num_aggressors_for_sync,
                            int total_num_activations) {

  // this is used by hammer_pattern but only for some stats calculations
  this->pattern_sync_each_ref = sync_each_ref;
  this->flushing_strategy = flushing;
  this->fencing_strategy = fencing;
  this->total_activations = total_num_activations;
  this->num_aggs_for_sync = num_aggressors_for_sync;

  // decides the number of aggressors of the beginning/end to be used for detecting the refresh interval
  // e.g., 10 means use the first 10 aggs in aggressor_pairs (repeatedly, if necessary) to detect the start refresh
  // (i.e., at the beginning) and the last 10 aggs in aggressor_pairs to detect the last refresh (at the end);
  const auto NUM_TIMED_ACCESSES = num_aggressors_for_sync;

  // check whether the NUM_TIMED_ACCESSES value works at all - otherwise just return from this function
  // this is safe as hammer_pattern checks whether there's a valid jitted function
  if (static_cast<size_t>(NUM_TIMED_ACCESSES) > aggressor_pairs.size()) {
    Logger::log_error(format_string("NUM_TIMED_ACCESSES (%d) is larger than #aggressor_pairs (%zu).",
        NUM_TIMED_ACCESSES,
        aggressor_pairs.size()));
    return;
  }

  // some sanity checks
  if (fn!=nullptr) {
    Logger::log_error(
        "Function pointer is not NULL, cannot continue jitting code without leaking memory. Did you forget to call cleanup() before?");
    exit(1);
  }

#ifdef ENABLE_JITTING
  asmjit::CodeHolder code;
  code.init(runtime.environment());
  code.setLogger(logger);
  asmjit::x86::Assembler a(&code);

  asmjit::Label while1_begin = a.newLabel();
  asmjit::Label while1_end = a.newLabel();
  asmjit::Label for_begin = a.newLabel();
  asmjit::Label for_end = a.newLabel();

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // warmup
  for (int idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.mov(asmjit::x86::rbx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  a.bind(while1_begin);
  // clflushopt addresses involved in sync
  for (int idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();

  // retrieve timestamp
  a.rdtscp();  // result of rdtscp is in [edx:eax]
  a.lfence();
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);  // discard upper 32 bits, store lower 32b in ebx for later

  // use first NUM_TIMED_ACCESSES addresses for sync
  for (int idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // if ((after - before) > 1000) break;
  a.rdtscp();  // result: edx:eax
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t) 1000);

  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  a.jg(while1_end);
  a.jmp(while1_begin);
  a.bind(while1_end);

  // ------- part 2: perform hammering ---------------------------------------------------------------------------------

  // initialize variables
  a.mov(asmjit::x86::rsi, total_num_activations);
  a.mov(asmjit::x86::edx, 0);  // num activations counter

  a.bind(for_begin);
  a.cmp(asmjit::x86::rsi, 0);
  a.jle(for_end);

  // a map to keep track of aggressors that have been accessed before and need a fence before their next access
  std::unordered_map<uint64_t, bool> accessed_before;

  size_t cnt_total_activations = 0;

  // hammer each aggressor once
  for (int i = NUM_TIMED_ACCESSES; i < static_cast<int>(aggressor_pairs.size()) - NUM_TIMED_ACCESSES; i++) {
    auto cur_addr = (uint64_t) aggressor_pairs[i];

    if (accessed_before[cur_addr]) {
      // flush
      if (flushing==FLUSHING_STRATEGY::LATEST_POSSIBLE) {
        a.mov(asmjit::x86::rax, cur_addr);
        a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
        accessed_before[cur_addr] = false;
      }
      // fence to ensure flushing finished and defined order of aggressors is guaranteed
      if (fencing==FENCING_STRATEGY::LATEST_POSSIBLE) {
        a.mfence();
        accessed_before[cur_addr] = false;
      }
    }

    // hammer
    a.mov(asmjit::x86::rax, cur_addr);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    accessed_before[cur_addr] = true;
    a.dec(asmjit::x86::rsi);
    cnt_total_activations++;

    // flush
    if (flushing==FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
      a.mov(asmjit::x86::rax, cur_addr);
      a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }
    if (sync_each_ref
        && ((cnt_total_activations%num_acts_per_trefi)==0)) {
      std::vector<volatile char *> aggs(aggressor_pairs.begin() + i,
          std::min(aggressor_pairs.begin() + i + NUM_TIMED_ACCESSES, aggressor_pairs.end()));
      sync_ref(aggs, a);
    }
  }

  // fences -> ensure that aggressors are not interleaved, i.e., we access aggressors always in same order
  a.mfence();

  // ------- part 3: synchronize with the end  -----------------------------------------------------------------------
  std::vector<volatile char *> last_aggs(aggressor_pairs.end() - NUM_TIMED_ACCESSES, aggressor_pairs.end());
  sync_ref(last_aggs, a);

  a.jmp(for_begin);
  a.bind(for_end);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  a.mov(asmjit::x86::eax, asmjit::x86::edx);
  a.ret();  // this is ESSENTIAL otherwise execution of jitted code creates a segfault

  // add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->corrupted_data());
#endif
#ifndef ENABLE_JITTING
  Logger::log_error("Cannot do code jitting. Set option ENABLE_JITTING to ON in CMakeLists.txt and do a rebuild.");
#endif
}

#ifdef ENABLE_JITTING
void CodeJitter::sync_ref(const std::vector<volatile char *> &aggressor_pairs, asmjit::x86::Assembler &assembler) {
  asmjit::Label wbegin = assembler.newLabel();
  asmjit::Label wend = assembler.newLabel();

  assembler.bind(wbegin);

  assembler.mfence();
  assembler.lfence();

  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result of rdtscp is in [edx:eax]
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);
  assembler.lfence();
  assembler.pop(asmjit::x86::edx);

  for (auto agg : aggressor_pairs) {
    // flush
    assembler.mov(asmjit::x86::rax, (uint64_t) agg);
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));

    // access
    assembler.mov(asmjit::x86::rax, (uint64_t) agg);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));

    // we do not deduct the sync aggressors from the total number of activations because the number of sync activations
    // varies for different patterns; if we deduct it from the total number of activations, we cannot ensure anymore
    // that we are hammering long enough/as many times as needed to trigger bit flips
//    assembler.dec(asmjit::x86::rsi);

    // update counter that counts the number of activation in the trailing synchronization
    assembler.inc(asmjit::x86::edx);
  }

  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result: edx:eax
  assembler.lfence();
  assembler.pop(asmjit::x86::edx);

  // if ((after - before) > 1000) break;
  assembler.sub(asmjit::x86::eax, asmjit::x86::ebx);
  assembler.cmp(asmjit::x86::eax, (uint64_t) 1000);

  // depending on the cmp's outcome...
  assembler.jg(wend);     // ... jump out of the loop
  assembler.jmp(wbegin);  // ... or jump back to the loop's beginning
  assembler.bind(wend);
}
#endif

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const CodeJitter &p) {
  j = {{"pattern_sync_each_ref", p.pattern_sync_each_ref},
       {"flushing_strategy", to_string(p.flushing_strategy)},
       {"fencing_strategy", to_string(p.fencing_strategy)},
       {"total_activations", p.total_activations},
       {"num_aggs_for_sync", p.num_aggs_for_sync}
  };
}

void from_json(const nlohmann::json &j, CodeJitter &p) {
  j.at("pattern_sync_each_ref").get_to(p.pattern_sync_each_ref);
  from_string(j.at("flushing_strategy"), p.flushing_strategy);
  from_string(j.at("fencing_strategy"), p.fencing_strategy);
  j.at("total_activations").get_to(p.total_activations);
  j.at("num_aggs_for_sync").get_to(p.num_aggs_for_sync);
}

#endif
