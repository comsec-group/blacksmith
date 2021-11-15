#include "Fuzzer/AggressorAccessPattern.hpp"

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const AggressorAccessPattern &p) {
  j = nlohmann::json{{"frequency", p.frequency},
                     {"amplitude", p.amplitude},
                     {"start_offset", p.start_offset},
                     {"aggressors", Aggressor::get_agg_ids(p.aggressors)}
  };
}

void from_json(const nlohmann::json &j, AggressorAccessPattern &p) {
  j.at("frequency").get_to(p.frequency);
  j.at("amplitude").get_to(p.amplitude);
  j.at("start_offset").get_to(p.start_offset);
  std::vector<AGGRESSOR_ID_TYPE> agg_ids;
  j.at("aggressors").get_to(agg_ids);
  p.aggressors = Aggressor::create_aggressors(agg_ids);
}

#endif

bool operator==(const AggressorAccessPattern &lhs, const AggressorAccessPattern &rhs) {
  return
      lhs.frequency==rhs.frequency &&
          lhs.amplitude==rhs.amplitude &&
          lhs.start_offset==rhs.start_offset &&
          // actually we should compare the aggressors here but we skip that because it would require us to implement a
          // comparison function for Aggressor too
          lhs.aggressors.size()==rhs.aggressors.size();
}

std::string AggressorAccessPattern::to_string() const {
  // creates a string of aggressor IDs like (id1, id2, ...)
  std::stringstream aggs;
  aggs << "(";
  for (const auto &agg : aggressors) {
    aggs << agg.id;
    if (agg.id!=(*aggressors.rbegin()).id) aggs << ",";
  }
  aggs << "): ";

  std::stringstream ss;
  ss << aggs.str() << frequency << ", " << amplitude << "⨉, " << start_offset;
  return ss.str();
}

AggressorAccessPattern &AggressorAccessPattern::operator=(const AggressorAccessPattern &other) {
  if (this == &other) return *this;
  this->frequency = other.frequency;
  this->amplitude = other.amplitude;
  this->start_offset = other.start_offset;
  this->aggressors = other.aggressors;
  return *this;
}
