#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/HammeringPattern.hpp"

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const HammeringPattern &p) {
  j = nlohmann::json{{"id", p.instance_id},
                     {"base_period", p.base_period},
                     {"max_period", p.max_period},
                     {"total_activations", p.total_activations},
                     {"num_refresh_intervals", p.num_refresh_intervals},
                     {"access_ids", Aggressor::get_agg_ids(p.aggressors)},
                     {"agg_access_patterns", p.agg_access_patterns},
                     {"address_mappings", p.address_mappings},
                     {"is_location_dependent", p.is_location_dependent}
  };
}

void from_json(const nlohmann::json &j, HammeringPattern &p) {
  j.at("id").get_to(p.instance_id);
  j.at("base_period").get_to(p.base_period);
  j.at("max_period").get_to(p.max_period);
  j.at("total_activations").get_to(p.total_activations);
  j.at("num_refresh_intervals").get_to(p.num_refresh_intervals);
  j.at("is_location_dependent").get_to(p.is_location_dependent);

  std::vector<AGGRESSOR_ID_TYPE> agg_ids;
  j.at("access_ids").get_to<std::vector<AGGRESSOR_ID_TYPE>>(agg_ids);
  p.aggressors = Aggressor::create_aggressors(agg_ids);

  j.at("agg_access_patterns").get_to<std::vector<AggressorAccessPattern>>(p.agg_access_patterns);
  j.at("address_mappings").get_to<std::vector<PatternAddressMapper>>(p.address_mappings);
}

#endif

HammeringPattern::HammeringPattern(int base_period)
    : instance_id(uuid::gen_uuid()),
      base_period(base_period),
      max_period(0),
      total_activations(0),
      num_refresh_intervals(0),
      is_location_dependent(false) {}

HammeringPattern::HammeringPattern()
    : instance_id(uuid::gen_uuid()),
      base_period(0),
      max_period(0),
      total_activations(0),
      num_refresh_intervals(0),
      is_location_dependent(false) {}

int HammeringPattern::get_num_digits(size_t x) {
  return (x < 10 ? 1 :
          (x < 100 ? 2 :
           (x < 1000 ? 3 :
            (x < 10000 ? 4 :
             (x < 100000 ? 5 :
              (x < 1000000 ? 6 :
               (x < 10000000 ? 7 :
              (x < 100000000 ? 8 :
                 (x < 1000000000 ? 9 : 10)))))))));
}

std::string HammeringPattern::get_pattern_text_repr() {
  std::stringstream ss;
  // depending on the number of aggressors, decide how many digits to use to represent each aggressor ID
  // we assume that if we have more than two AggressorAccessPatterns, then it is fully filled pattern and we can just
  // use the number of aggressors as a way to determine how many digits we need, otherwise it's probably a
  // empty/prefilled pattern and we assume 2 digits (as ID_PLACEHOLDER_AGG is -1)
  auto dwidth = (agg_access_patterns.size() > 2) ? get_num_digits(aggressors.size()) : 2;
  for (size_t i = 0; i < aggressors.size(); ++i) {
    // add a new line after each base period to make it easier to check a pattern's correctness
    if ((i%base_period)==0 && i > 0) ss << std::endl;
    ss << std::setfill('0') << std::setw(dwidth) << aggressors.at(i).id << " ";
  }
  return ss.str();
}

std::string HammeringPattern::get_agg_access_pairs_text_repr() {
  std::stringstream ss;
  auto cnt = 0;
  for (const auto &agg_acc_pair : agg_access_patterns) {
    // add a new line after each three aggressor access patterns to avoid unintended text wrapping in terminal
    if (cnt > 0 && cnt%3==0) ss << std::endl;
    ss << std::setw(30) << std::setfill(' ') << std::left << agg_acc_pair.to_string();
    cnt++;
  }
  return ss.str();
}

AggressorAccessPattern &HammeringPattern::get_access_pattern_by_aggressor(Aggressor &agg) {
  // iterate over the AggressorAccessPatterns and return the *first* AggressorAccessPattern that has the given Aggressor
  // agg as its *first* Aggressor
  for (auto &aap : agg_access_patterns) {
    if (aap.aggressors[0].id==agg.id) return aap;
  }
  Logger::log_error(format_string("Could not find AggressorAccessPattern whose first aggressor has id %s.", agg.id));
  exit(1);
}

PatternAddressMapper &HammeringPattern::get_most_effective_mapping() {
  if (address_mappings.empty()) {
    Logger::log_error("get_most_effective_mapping() failed: No mappings existing!");
    exit(EXIT_FAILURE);
  }
  PatternAddressMapper &best_mapping = address_mappings.front();
  for (const auto& mapping : address_mappings) {
    if (mapping.count_bitflips() > best_mapping.count_bitflips()) {
      best_mapping = mapping;
    }
  }
  return best_mapping;
}

void HammeringPattern::remove_mappings_without_bitflips() {
  for (auto it = address_mappings.begin(); it != address_mappings.end(); ) {
    if (it->count_bitflips() == 0) {
      it = address_mappings.erase(it);
    } else {
      it++;
    }
  }
}
