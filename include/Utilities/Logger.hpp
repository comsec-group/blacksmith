/*
 * Copyright (c) 2021 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_LOGGER_HPP_
#define BLACKSMITH_INCLUDE_LOGGER_HPP_

#include <string>
#include <fstream>
#include <memory>

template<typename ... Args>
std::string format_string(const std::string &format, Args ... args) {
  int size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
  if (size <= 0) { throw std::runtime_error("Error during formatting."); }
  std::unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), static_cast<size_t>(size), format.c_str(), args ...);
  return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

class Logger {
 private:
  Logger();

  // a reference to the file output stream associated to the logfile
  std::ofstream logfile;

  // the logger instance (a singleton)
  static Logger instance;

  static std::string format_timestamp(unsigned long ts);

  unsigned long timestamp_start{};

 public:

  static void initialize();

  static void close();

  static void log_info(const std::string &message, bool newline = true);

  static void log_highlight(const std::string &message, bool newline = true);

  static void log_error(const std::string &message, bool newline = true);

  static void log_data(const std::string &message, bool newline = true);

  static void log_bitflip(volatile char *flipped_address, uint64_t row_no, unsigned char actual_value,
                          unsigned char expected_value, unsigned long timestamp, bool newline);

  static void log_debug(const std::string &message, bool newline = true);

  static void log_timestamp();

  static void log_global_defines();

  static void log_metadata(const char *commit_hash, unsigned long run_time_limit_seconds);

  static void log_analysis_stage(const std::string &message, bool newline = true);

  static void log_success(const std::string &message, bool newline = true);

  static void log_failure(const std::string &message, bool newline = true);
};

#endif //BLACKSMITH_INCLUDE_LOGGER_HPP_
