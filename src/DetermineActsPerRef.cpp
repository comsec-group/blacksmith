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
#include "argagg/argagg.hpp"

// defines the program's arguments and their default values
struct ProgramArguments {
  // path to JSON config
  std::string config;
  // path to measurements output
  std::string output;
  // number of measurement rounds
  size_t rounds;
};

struct ProgramArguments program_args;

void handle_args(int argc, char **argv);

int main(int argc, char** argv) {
  Logger::initialize("/dev/stdout");

  Logger::log_info("Parsing args");
  handle_args(argc, argv);

  //BlacksmithConfig needs: num banks, threshold
  BlacksmithConfig config = BlacksmithConfig::from_jsonfile(program_args.config);

  Logger::log_config(config);

  Logger::log_info("Allocation memory");

  Memory memory(config, true);
  memory.allocate_memory();
  memset((void*)memory.get_starting_address(), 0, memory.get_size());
  DramAnalyzer dram_analyzer(config, memory.get_starting_address());
  Logger::log_info("Loading DRAM config");
  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::set_config(config);
  DRAMAddr::initialize(memory.get_starting_address());

  auto addr1 = DRAMAddr((void*)(memory.get_starting_address()));
  auto addr2 = addr1.add(0, 1, 0);
  Logger::log_info(format_string("Choose %s and %s as row conflict addresses", addr1.to_string().c_str(), addr2.to_string().c_str()));

  size_t timings[program_args.rounds];
  char *a1 = static_cast<char*>(addr1.to_virt());
  char *a2 = static_cast<char*>(addr1.to_virt());
  for (size_t i = 0; i < program_args.rounds; ++i) {
    timings[i] = DramAnalyzer::measure_time(a1, a2, 1);
  }

  Logger::log_info(format_string("Writing acts per ref to file %s", program_args.output.c_str()));

  std::ofstream outFile;
  outFile.open(program_args.output);
  outFile << "access time in cycles" << std::endl;
  for(size_t timing: timings) {
    outFile << timing << std::endl;
  }
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
                                "sets the path for access timing measurements (default: acts-per-ref.csv)", 1},
                               {"rounds", {"-r", "--rounds"},
                                "number of measurement rounds (default: 1000)", 1},
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
    program_args.output = "acts-per-ref.csv";
  }
  Logger::log_debug(format_string("Set --output=%s", program_args.output.c_str()));

  if (parsed_args.has_option("rounds")) {
    program_args.rounds = parsed_args["rounds"].as<size_t>(1000);
  } else {
    program_args.rounds = 1000;
  }
  Logger::log_debug(format_string("Set --rounds=%u", program_args.rounds));
}