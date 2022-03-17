//
// Created by Luca Wilke on 17.03.22.
// Small tool to determine the row conflict timing. This is required as an
// input into the blacksmith fuzzer
//

#include<iostream>
#include "Memory/Memory.hpp"

int main() {
  Logger::initialize();
  std::cerr << "Allocating memory...";

  Memory memory(true);
  memory.allocate_memory(MEM_SIZE, false, false);
  memset((void*)memory.get_starting_address(), 0, MEM_SIZE);

  std::cerr << "done\nMeasuring access timings using "<< GlobalConfig.getDramaRounds() <<" rounds per measurement ...";

  DramAnalyzer dram_analyzer(memory.get_starting_address());
  auto timings = dram_analyzer.measure_timings(10000);

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