#include "Fuzzer/Aggressor.hpp"

#include <unordered_map>

std::string Aggressor::to_string() const {
  if (id==ID_PLACEHOLDER_AGG) return "EMPTY";
  std::stringstream ss;
  ss << "agg" << std::setfill('0') << std::setw(2) << id;
  return ss.str();
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const Aggressor &p) {
  j = nlohmann::json{{"id", p.id}};
}

void from_json(const nlohmann::json &j, Aggressor &p) {
  j.at("id").get_to(p.id);
}

#endif

std::vector<AGGRESSOR_ID_TYPE> Aggressor::get_agg_ids(const std::vector<Aggressor> &aggressors) {
  std::vector<AGGRESSOR_ID_TYPE> agg_ids;
  agg_ids.reserve(aggressors.size());
  for (const auto &agg : aggressors) agg_ids.push_back(agg.id);
  return agg_ids;
}

Aggressor::Aggressor(int id) : id(id) {}

std::vector<Aggressor> Aggressor::create_aggressors(const std::vector<AGGRESSOR_ID_TYPE> &agg_ids) {
  std::vector<Aggressor> result_list;
  std::unordered_map<AGGRESSOR_ID_TYPE, Aggressor> aggId_to_aggressor_map;

  for (const auto &id : agg_ids) {
    if (aggId_to_aggressor_map.count(id)==0) {
      aggId_to_aggressor_map[id] = Aggressor(id);
    }
    result_list.push_back(aggId_to_aggressor_map.at(id));
  }

  return result_list;
}

Aggressor &Aggressor::operator=(const Aggressor &other) {
  if (this == &other) return *this;
  this->id = other.id;
  return *this;
}
