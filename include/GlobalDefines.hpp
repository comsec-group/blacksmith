#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <sstream>

#include "Utilities/Logger.hpp"

uint64_t static inline MB(uint64_t value) {
  return ((value) << 20ULL);
}

uint64_t static inline GB(uint64_t value) {
  return ((value) << 30ULL);
}

[[gnu::unused]] static inline uint64_t BIT_SET(uint64_t value) {
  return (1ULL << (value));
}

// font colors
#define FC_RED "\033[0;31m"         // error
#define FC_RED_BRIGHT "\033[0;91m"  // generic failure message
#define FC_GREEN "\033[0;32m"       // bit flip, generic success message
#define FC_YELLOW "\033[0;33m"      // debugging
#define FC_MAGENTA "\033[0;35m"     // new (pattern,address_mapping) rond
#define FC_CYAN "\033[0;36m"        // status message
#define FC_CYAN_BRIGHT "\033[0;96m" // stages in pattern analysis

// font faces
#define FF_BOLD "\033[1m"
#define F_RESET "\033[0m" // reset to default font face/color

// ########################################################
// ################### CONFIG PARAMETERS ##################
// ########################################################

// number of rounds to measure cache hit/miss latency
#define DRAMA_ROUNDS 1000

// size in bytes of a cacheline
#define CACHELINE_SIZE 64

// number of rounds to hammer
#define HAMMER_ROUNDS 1000000

// threshold to distinguish between cache miss (t > THRESH) and cache hit (t < THRESH)
#define THRESH 330  // luca: N.B. that we have different timing function than orig blacksmith

// number of conflicting addresses to be determined for each bank
#define NUM_TARGETS 10

// maximum number of aggressor rows
#define MAX_ROWS 30

// number of banks in the system. luca: we search for NUM_BANKS sets/pools of conflicting addrs in 
//void DramAnalyzer::find_bank_conflicts. Thus this should be RANK*BANK e.g. number of sets e.g. 32 if we have 2 Ranks with 16 banks
//but i am not 100% sure. Make sure this is in sync with the supplied DRAM config
#define NUM_BANKS 32


#endif /* GLOBAL_DEFINES */
