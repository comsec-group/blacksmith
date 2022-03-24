//
// Created by Luca Wilke on 18.03.22.
//

//
// Created by Luca Wilke on 17.03.22.
// Small tool to determine the number of activatiosn per refresh interval. This is also done at the start (and periodically
// during the runtiem) of blacksmith. However, a separate program makes it easier to analyse this
//

#include<iostream>
#include "Memory/Memory.hpp"

int main(int argc, char** argv) {
  Logger::initialize();

  if( argc != 3) {
    std::cout << "Usage: determineActsPerRef <total bank count> <row conflict threshold>";
    return 1;
  }

  GlobalConfig.setNumBanks(atoi(argv[1]));
  GlobalConfig.setThresh(atoi(argv[2]));
  GlobalConfig.lock();
  Logger::log_global_defines();
  std::cerr << "Allocating memory...";

  Memory memory(true);
  memory.allocate_memory(MEM_SIZE, false, false);
  memset((void*)memory.get_starting_address(), 0, MEM_SIZE);
  DramAnalyzer dram_analyzer(memory.get_starting_address());
  std::cerr << "done\nDetermining bank conflicts...";

  dram_analyzer.find_bank_conflicts();
  std::cerr << "done\n Determining acts per ref...";
  for( int i = 0; i < 10;i++) {
    std::cout << "\n" << dram_analyzer.count_acts_per_ref()*2 << "\n";
  }
  std::cerr << "done\nThis is goodbye\n";
}