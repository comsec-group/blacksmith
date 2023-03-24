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

  const size_t sampleSize = 10000;
  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> timings;
  timings.reserve(sampleSize);

  Logger::log_info("Start sampling process, this might take a while...");
  for( int bank = 3; bank < 4; bank++) {
    //loop over all row combinations
    for(int rowA = 0; rowA < DRAMAddr::get_row_count(); rowA++) {
      Logger::log_info(format_string("outer row %d out of %d",rowA,DRAMAddr::get_row_count()));
      for(int rowB = rowA+1; rowB < DRAMAddr::get_row_count(); rowB++) {
        auto addrA = DRAMAddr(bank,rowA,0);
        auto addrB = DRAMAddr(bank,rowB,0);
        auto timing = DramAnalyzer::measure_time((volatile char*)addrA.to_virt(),(volatile char*)addrB.to_virt(), config.drama_rounds);

        timings.emplace_back(std::make_tuple(
                reinterpret_cast<std::uintptr_t>(addrA.to_virt()),
                reinterpret_cast<std::uintptr_t>(addrB.to_virt()),
                timing ));
      }
    }
  }

  Logger::log_info(format_string("Writing measurements to %s", program_args.output.c_str()));

  std::ofstream outFile;
  outFile.open(program_args.output);
  outFile << "addr1,addr2,timing" << std::endl;
  for( auto & tuple : timings) {
    outFile << std::get<0>(tuple) << "," << std::get<1>(tuple) << "," <<std::get<2>(tuple) << std::endl;
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
                                "sets the path for access timing measurements (default: access-timings.csv)", 1}
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
    program_args.output = "access-timings.csv";
  }
  Logger::log_debug(format_string("Set --output=%s", program_args.output.c_str()));
}