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
  // number of samples for row hit
  size_t samples_hit;
  // number of samples for row miss
  size_t samples_miss;
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

  std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> timings;
  timings.reserve(program_args.samples_hit + program_args.samples_miss);
  //
  // Measure row hit timing
  //
  auto a1 = DRAMAddr((void *) memory.get_starting_address());
  auto *a1_row_hit = (volatile char *) a1.add(0, 0, 1).to_virt();
  Logger::log_info(format_string("Measuring %lu samples for same row", program_args.samples_hit));

  for (size_t sampleIdx = 0; sampleIdx < program_args.samples_hit; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char *) a1.to_virt(), a1_row_hit, config.drama_rounds);
    timings.emplace_back(
        std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()), reinterpret_cast<std::uintptr_t>(a1_row_hit),
                        timing));
  }

  //
  //Measure row conflict timing
  //
  auto *a1_row_conflict = (volatile char *) a1.add(0, 1, 0).to_virt();
  Logger::log_info(format_string("Measuring %lu samples for differing rows", program_args.samples_miss));
  for (size_t sampleIdx = 0; sampleIdx < program_args.samples_miss; sampleIdx++) {
    auto timing = DramAnalyzer::measure_time((volatile char *) a1.to_virt(), a1_row_conflict, config.drama_rounds);
    timings.emplace_back(std::make_tuple(reinterpret_cast<std::uintptr_t>(a1.to_virt()),
                                         reinterpret_cast<std::uintptr_t>(a1_row_conflict), timing));
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
                                "sets the path for access timing measurements (default: access-timings.csv)", 1},
                               {"samples-hit", {"--samples-hit"},
                                "set the number of samples for row buffer hits (default: 10000)", 1},
                               {"samples-miss", {"--samples-miss"},
                                "set the number of samples for row buffer miss (default: 10000)", 1},
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

  if (parsed_args.has_option("samples-hit")) {
    program_args.samples_hit = parsed_args["samples"].as<size_t>(0);
  } else {
    program_args.samples_hit = 10000;
  }
  Logger::log_debug(format_string("Set --samples-hit=%lu", program_args.samples_hit));

  if (parsed_args.has_option("samples-miss")) {
    program_args.samples_miss = parsed_args["samples-miss"].as<size_t>(0);
  } else {
    program_args.samples_miss = 10000;
  }
  Logger::log_debug(format_string("Set --samples-miss=%lu", program_args.samples_miss));

}