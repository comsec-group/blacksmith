//
// Created by Luca Wilke on 17.03.22.
// Small tool to determine the row conflict timing. This is required as an
// input into the blacksmith fuzzer
//

#include<iostream>
#include "Memory/Memory.hpp"
#include "Memory/DramAnalyzer.hpp"
#include "argagg/argagg.hpp"

// defines the program's arguments and their default values
struct ProgramArguments {
  // path to JSON config
  std::string config;
  // path to CSV output
  std::string output;
};

ProgramArguments program_args;

void handle_args(int argc, char **argv);

int main(int argc, char **argv) {
  Logger::initialize("/dev/stdout");

  handle_args(argc, argv);

  BlacksmithConfig config = BlacksmithConfig::from_jsonfile(program_args.config);

  Logger::log_info("Allocating memory...");

  Memory memory(config, true);
  memory.allocate_memory();
  Logger::log_info("Initializing memory...");
  memset((void*)memory.get_starting_address(), 0, memory.get_size());
  Logger::log_info("Loading dram config...");
  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::set_config(config);
  DRAMAddr::initialize(memory.get_starting_address());

  const size_t bank_count = DRAMAddr::get_bank_count();
  const size_t row_count = DRAMAddr::get_row_count();

  Logger::log_info("Start sampling process, this might take a while...");
  Logger::log_info(format_string("Writing measurements to %s", program_args.output.c_str()));
  std::ofstream outFile;
  outFile.open(program_args.output);
  outFile << "bank,rowA,rowB,addrA,addrB,timing" << std::endl;
  for(size_t bank = 0; bank < bank_count; bank++) {
    //loop over all row combinations
    for(size_t rowA = 0; rowA < row_count; rowA++) {
      Logger::log_info(format_string("outer row %lu:%d of %lu:%d",bank, rowA, bank_count-1, row_count-1));
      for(size_t rowB = rowA+1; rowB < row_count; rowB++) {
        auto addrA = DRAMAddr(bank,rowA,0);
        auto addrB = DRAMAddr(bank,rowB,0);
        auto timing = DramAnalyzer::measure_time((volatile char*)addrA.to_virt(),(volatile char*)addrB.to_virt(), config.drama_rounds);
        outFile << bank << ","
                << rowA << ","
                << rowB << ","
                << reinterpret_cast<std::uintptr_t>(addrA.to_virt()) << ","
                << reinterpret_cast<std::uintptr_t>(addrB.to_virt()) << ","
                << timing << std::endl;
        if(timing < config.threshold) {
          Logger::log_error(format_string("Measured %lu for addresses %lu (bank %lu, row %lu) "
                                          "and %lu (bank %lu, row %lu), which is below the row conflict threshold of %lu",
                                          timing,
                                          reinterpret_cast<std::uintptr_t>(addrA.to_virt()), bank, rowA,
                                          reinterpret_cast<std::uintptr_t>(addrB.to_virt()), bank, rowB,
                                          config.threshold));
        }
      }
    }
  }
  outFile.close();
  Logger::log_info("Done, goodbye!");
}

void handle_args(int argc, char **argv) {
  // An option is specified by four things:
  //    (1) the name of the option,
  //    (2) the strings that activate the option (flags),
  //    (3) the option's help message,
  //    (4) and the number of arguments the option expects.
  argagg::parser argparser{{
                               {"help", {"-h", "--help"}, "shows this help message", 0},

                               {"config", {"-c", "--config"},
                                "loads the specified config file (JSON) as DRAM address config.", 1},
                               {"output", {"-o", "--output"},
                                "sets the path for access timing measurements (default: row-access-timings.csv)", 1},
                           }};

  argagg::parser_results parsed_args;
  try {
    parsed_args = argparser.parse(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    exit(EXIT_FAILURE);
  }

  if (parsed_args["help"]) {
    std::cerr << argparser;
    exit(EXIT_SUCCESS);
  }

  /**
   * mandatory parameters
   */
  if (parsed_args.has_option("config")) {
    program_args.config = parsed_args["config"].as<std::string>("");
    Logger::log_debug(format_string("Set --config=%s", program_args.config.c_str()));
  } else {
    Logger::log_error("Program argument '--config <string>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }

  /**
   * optional parameters
   */
  if (parsed_args.has_option("output")) {
    program_args.output = parsed_args["output"].as<std::string>("");
  } else {
    program_args.output = "row-access-timings.csv";
  }
  Logger::log_debug(format_string("Set --output=%s", program_args.output.c_str()));
}