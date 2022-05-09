//
// Created by Luca Wilke on 17.03.22.
// Small tool to determine the row conflict timing. This is required as an
// input into the blacksmith fuzzer
//

#include<iostream>
#include "Memory/Memory.hpp"
#include "Memory/DramAnalyzer.hpp"


int main() {
  Logger::initialize();
  std::cerr << "Allocating memory...";

  Memory memory(true);
  memory.allocate_memory(MEM_SIZE, true);
  memset((void*)memory.get_starting_address(), 0, MEM_SIZE);
  Logger::log_info("loading dram config");
  // initialize the DRAMAddr class to load the proper memory configuration
  //luca initialize the global Config variable for memory with the data from the config file we edited
  std::string identifier = "itsepyc2";
  GlobalConfig.setNumBanks(16);
  DRAMAddr::initialize(identifier, 2, memory.get_starting_address());

  const size_t sampleSize = 10000;
  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> timings;
  timings.reserve(3*sampleSize);
  //
  // Measure row hit timing
  //
  Logger::log_info("searching row hit entry...");
  auto a1 = DRAMAddr((void*)memory.get_starting_address());
  volatile char*  a1_row_hit;
  for(uint8_t* ptr = (uint8_t*)memory.get_starting_address()+4096; ptr < ((uint8_t *)memory.get_starting_address())+memory.getSize(); ptr += 64) {
    auto candidate_dram = DRAMAddr((void*)ptr);
    if( a1.bank == candidate_dram.bank && a1.row == candidate_dram.row) {
      a1_row_hit = (volatile char*)candidate_dram.to_virt();
      break;
    }
  }
  Logger::log_info("found same row entry. Measuring...");

  for( size_t sampleIdx = 0; sampleIdx < 100000; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char*)a1.to_virt(), a1_row_hit);
    timings.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()),reinterpret_cast<std::uintptr_t>(a1_row_hit),timing ));
  }

  //
  //Measure row conflict timing
  //

  Logger::log_info("searching row conflict entry... ");
  volatile char*  a1_row_conflict;
  for(uint8_t* ptr = (uint8_t*)memory.get_starting_address()+4096; ptr < ((uint8_t *)memory.get_starting_address())+memory.getSize(); ptr += 64) {
    auto candidate_dram = DRAMAddr((void*)ptr);
    if( a1.bank == candidate_dram.bank && a1.row != candidate_dram.row) {
      a1_row_conflict = (volatile char*)candidate_dram.to_virt();
      break;
    }
  }
  Logger::log_info("found row conflict entry. Measuring...");
  for( size_t sampleIdx = 0; sampleIdx < 100000; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char*)a1.to_virt(), a1_row_conflict);
    timings.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()),reinterpret_cast<std::uintptr_t>(a1_row_conflict),timing ));
  }


  std::cerr << "done\nWriting csv file ...";;

  std::ofstream outFile;
  outFile.open("access-timings.csv");
  outFile << "timing\n";
  for( auto & tuple : timings) {
    outFile << std::get<2>(tuple) <<"\n";
  }
  outFile.close();
  std::cerr << "done\nThis is goodbye" << std::endl;
}