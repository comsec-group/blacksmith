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
  std::cerr << "Initializing memory...";
  memset((void*)memory.get_starting_address(), 0, MEM_SIZE);
  Logger::log_info("loading dram config");
  // initialize the DRAMAddr class to load the proper memory configuration
  //luca initialize the global Config variable for memory with the data from the config file we edited
  std::string identifier = "xeon2";
  GlobalConfig.setNumBanks(32);
  DRAMAddr::initialize(identifier, 2, memory.get_starting_address());
  std::cerr << "init done\n";

  const size_t sampleSize = 10000;
  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> timings;
  timings.reserve(sampleSize);

  Logger::log_info("start sampling process, this might take a while...");
  for( int bank = 3; bank < 4; bank++) {
    //loop over all row combinations
    for(int rowA = 0; rowA < DRAMAddr::get_row_count(); rowA++) {
      Logger::log_info(format_string("outer row %d out of %d",rowA,DRAMAddr::get_row_count()));
      for(int rowB = rowA+1; rowB < DRAMAddr::get_row_count(); rowB++) {
        auto addrA = DRAMAddr(bank,rowA,0);
        auto addrB = DRAMAddr(bank,rowB,0);
        auto timing = DramAnalyzer::measure_time((volatile char*)addrA.to_virt(),(volatile char*)addrB.to_virt());

        timings.emplace_back(std::make_tuple(
                reinterpret_cast<std::uintptr_t>(addrA.to_virt()),
                reinterpret_cast<std::uintptr_t>(addrB.to_virt()),
                timing ));
      }
    }
  }


    std::cerr << "done\nWriting csv file ...";;

  std::ofstream outFile;
  outFile.open("access-timings.csv");
  outFile << "timing\n";
  for( auto & tuple : timings) {
    outFile << std::get<0>(tuple) << "," << std::get<1>(tuple) << "," <<std::get<2>(tuple) <<"\n";
  }
  outFile.close();
  std::cerr << "done\nThis is goodbye" << std::endl;
}