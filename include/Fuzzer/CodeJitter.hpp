/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef CODEJITTER
#define CODEJITTER

#include <unordered_map>
#include <vector>

#include "Utilities/Enums.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

#ifdef ENABLE_JITTING
#include <asmjit/asmjit.h>
#endif

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

class CodeJitter {
 private:
#ifdef ENABLE_JITTING
  /// runtime for JIT code execution, can be reused by cleaning the function ptr (see cleanup method)
  asmjit::JitRuntime runtime;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  asmjit::StringLogger *logger = nullptr;
#endif

  /// a function pointer to a function that takes no input (void) and returns an integer
  int (*fn)() = nullptr;

 public:
  bool pattern_sync_each_ref;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  int total_activations;

  int num_aggs_for_sync;

  /// constructor
  CodeJitter();
  
  /// destructor
  ~CodeJitter();

  /// generates the jitted function and assigns the function pointer fn to it
  void jit_strict(int num_acts_per_trefi,
                  FLUSHING_STRATEGY flushing,
                  FENCING_STRATEGY fencing,
                  const std::vector<volatile char *> &aggressor_pairs,
                  bool sync_each_ref,
                  int num_aggressors_for_sync,
                  int total_num_activations);

  /// does the hammering if the function was previously created successfully, otherwise does nothing
  int hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose);

  /// cleans this instance associated function pointer that points to the function that was jitted at runtime;
  /// cleaning up is required to release memory before jit_strict can be called again
  void cleanup();

#ifdef ENABLE_JITTING
  static void sync_ref(const std::vector<volatile char *> &aggressor_pairs, asmjit::x86::Assembler &assembler);
#endif
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const CodeJitter &p);

void from_json(const nlohmann::json &j, CodeJitter &p);

#endif

#endif /* CODEJITTER */
