//
// Created by Luca Wilke on 17.03.22.
// Small tool to determine the row conflict timing. This is required as an
// input into the blacksmith fuzzer
//

#include<iostream>
#include "Memory/Memory.hpp"
#include "Memory/DramAnalyzer.hpp"
#include "argagg/argagg.hpp"


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

  Logger::log_info("Parsing args");
  handle_args(argc, argv);

  BlacksmithConfig config = BlacksmithConfig::from_jsonfile(program_args.config);

  Logger::log_info("Allocating memory");

  Memory memory(config, true);
  memory.allocate_memory();
  memset((void*)memory.get_starting_address(), 0, memory.get_size());
  Logger::log_info("Loading dram config");

  DRAMAddr::set_config(config);
  DRAMAddr::initialize(memory.get_starting_address());

  const size_t sampleSize = 10000;
  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> timings;
  timings.reserve(3*sampleSize);
  //
  // Measure row hit timing
  //
  Logger::log_info("Searching row hit entry...");
  auto a1 = DRAMAddr((void*)memory.get_starting_address());
  volatile char*  a1_row_hit;
  for(uint8_t* ptr = (uint8_t*)memory.get_starting_address()+4096; ptr < ((uint8_t *)memory.get_starting_address())+memory.get_size(); ptr += 64) {
    auto candidate_dram = DRAMAddr((void*)ptr);
    if( a1.bank == candidate_dram.bank && a1.row == candidate_dram.row) {
      a1_row_hit = (volatile char*)candidate_dram.to_virt();
      break;
    }
  }
  Logger::log_info("Found same row entry. Measuring...");

  for( size_t sampleIdx = 0; sampleIdx < 100000; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char*)a1.to_virt(), a1_row_hit, config.drama_rounds);
    timings.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()),reinterpret_cast<std::uintptr_t>(a1_row_hit),timing ));
  }

  //
  //Measure row conflict timing
  //

  Logger::log_info("Searching row conflict entry... ");
  volatile char*  a1_row_conflict;
  for(uint8_t* ptr = (uint8_t*)memory.get_starting_address()+4096; ptr < ((uint8_t *)memory.get_starting_address())+memory.get_size(); ptr += 64) {
    auto candidate_dram = DRAMAddr((void*)ptr);
    if( a1.bank == candidate_dram.bank && a1.row != candidate_dram.row) {
      a1_row_conflict = (volatile char*)candidate_dram.to_virt();
      break;
    }
  }
  Logger::log_info("Found row conflict entry. Measuring...");
  for( size_t sampleIdx = 0; sampleIdx < 100000; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char*)a1.to_virt(), a1_row_conflict, config.drama_rounds);
    timings.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()),reinterpret_cast<std::uintptr_t>(a1_row_conflict),timing ));
  }


  Logger::log_info(format_string("Writing timings to file \"%s\"", program_args.output.c_str()));

  std::ofstream outFile;
  outFile.open(program_args.output);
  outFile << "timing" << std::endl;
  for( auto & tuple : timings) {
    outFile << std::get<2>(tuple) << std::endl;
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