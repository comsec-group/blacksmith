
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Memory/DRAMAddr.hpp"

namespace py = pybind11;

namespace
{
std::string
repr_dram_addr(const DRAMAddr& addr)
{
    return format_string("DRAMAddr(bank=%d, row=%d, column=%d)", addr.bank,
                         addr.row, addr.col);
}

std::string
repr_bit_flip(const BitFlip& flip)
{
    return format_string("BitFlip(addr=%s, corrupted_data=0x%0" PRIx8
                         ", mask=0x%0" PRIx8 ")",
                         repr_dram_addr(flip.address).c_str(),
                         flip.corrupted_data, flip.bitmask);
}

std::string
repr_aggressor(const Aggressor& agg)
{
    return format_string("Aggressor(id=%d)", agg.id);
}

std::string
repr_aggressor_access_pattern(const AggressorAccessPattern& access_pattern)
{
    std::string aggressors = "[";
    for (auto&& agg : access_pattern.aggressors) {
        aggressors += repr_aggressor(agg) + ", ";
    }
    if (!access_pattern.aggressors.empty()) {
        // Remove trailing ', '.
        aggressors.pop_back();
        aggressors.pop_back();
    }
    aggressors += "]";

    return format_string(
        "AggressorAccessPattern(aggressors=%s, amplitude=%d, frequency=%zu, "
        "start_offset=%zu)",
        aggressors.c_str(), access_pattern.amplitude, access_pattern.frequency,
        access_pattern.start_offset);
}

std::string
repr_pattern_address_mapper(const PatternAddressMapper& mapping)
{
    std::string aggressor_map = "{";
    for (auto&& pair : mapping.aggressor_to_addr) {
        aggressor_map += format_string("%d: %s, ", pair.first,
                                       repr_dram_addr(pair.second).c_str());
    }
    if (!mapping.aggressor_to_addr.empty()) {
        // Remove trailing ', '.
        aggressor_map.pop_back();
        aggressor_map.pop_back();
    }
    aggressor_map += "}";

    // TODO: add bit flips?
    return format_string(
        "Mapping(id=%s, aggressors=%s, bank=%d, min_row=%zu, max_row=%zu)",
        mapping.get_instance_id().c_str(), aggressor_map.c_str(),
        mapping.bank_no, mapping.min_row, mapping.max_row);
}

std::string
repr_hammering_pattern(const HammeringPattern& pattern)
{
    std::string agg_access_patterns = "[";
    for (auto&& agg_pattern : pattern.agg_access_patterns) {
        agg_access_patterns +=
            repr_aggressor_access_pattern(agg_pattern) + ", ";
    }
    if (!pattern.agg_access_patterns.empty()) {
        // Remove trailing ', '.
        agg_access_patterns.pop_back();
        agg_access_patterns.pop_back();
    }
    agg_access_patterns += "]";

    std::string aggressors = "[";
    for (auto&& agg : pattern.aggressors) {
        aggressors += repr_aggressor(agg) + ", ";
    }
    if (!pattern.aggressors.empty()) {
        // Remove trailing ', '.
        aggressors.pop_back();
        aggressors.pop_back();
    }
    aggressors += "]";

    std::string mappings = "[";
    for (auto&& mapping : pattern.address_mappings) {
        mappings += repr_pattern_address_mapper(mapping) + ", ";
    }
    if (!pattern.address_mappings.empty()) {
        // Remove trailing ', '.
        mappings.pop_back();
        mappings.pop_back();
    }
    mappings += "]";

    return format_string(
        "Pattern(id=%s, access_patterns=%s, aggressors=%s, base_period=%d, "
        "mappings=%s, max_period=%zu, num_refresh_intervals=%d, "
        "total_activations=%d)",
        pattern.instance_id.c_str(), agg_access_patterns.c_str(),
        aggressors.c_str(), pattern.base_period, mappings.c_str(),
        pattern.max_period, pattern.num_refresh_intervals,
        pattern.total_activations);
}

std::string
repr_fuzzing_parameter_set(const FuzzingParameterSet& params)
{
    return format_string(
        "FuzzingParameterSet(agg_inter_distance=%d, base_period=%d, "
        "num_aggressors=%d, num_refresh_intervals=%d, "
        "total_acts_pattern=%d)",
        params.get_base_period(), params.get_agg_inter_distance(),
        params.get_num_aggressors(), params.get_num_refresh_intervals(),
        params.get_total_acts_pattern());
}

void
params_randomize(FuzzingParameterSet& params)
{
    params.randomize_parameters(false);
}

HammeringPattern
params_gen_pattern(FuzzingParameterSet& params, int num_mappings)
{
    auto pattern = HammeringPattern(params.get_base_period());
    PatternBuilder pattern_builder(pattern);
    pattern_builder.generate_frequency_based_pattern(params);

    std::random_device rd;
    std::mt19937 gen(rd());

    std::shuffle(pattern.agg_access_patterns.begin(),
                 pattern.agg_access_patterns.end(), gen);

    for (int i = 0; i < num_mappings; ++i) {
        PatternAddressMapper mapping;
        mapping.randomize_addresses(params, pattern.agg_access_patterns, false);
        pattern.address_mappings.push_back(mapping);
    }

    return pattern;
}

PYBIND11_MODULE(_blacksmith, mod)
{
    mod.doc() = "Python bindings for native Blacksmith functionality.";

    // DRAMAddr(size_t bk, size_t r, size_t c);
    py::class_<DRAMAddr>(mod, "DRAMAddress")
        .def(py::init<size_t, size_t, size_t>(), py::arg("bank"),
             py::arg("row"), py::arg("column"))
        .def_readonly("bank", &DRAMAddr::bank)
        .def_readonly("column", &DRAMAddr::col)
        .def_readonly("row", &DRAMAddr::row)
        .def("__repr__", repr_dram_addr);

    // BitFlip(const DRAMAddr &address, uint8_t flips_bitmask, uint8_t
    // corrupted_data);
    py::class_<BitFlip>(mod, "BitFlip")
        .def(py::init<const DRAMAddr&, uint8_t, uint8_t>(), py::arg("address"),
             py::arg("mask"), py::arg("corrupted_data"))
        .def_readonly("addr", &BitFlip::address)
        .def_readonly("corrupted_data", &BitFlip::corrupted_data)
        .def_readonly("mask", &BitFlip::bitmask)
        .def("__repr__", repr_bit_flip);

    // Aggressor(int id);
    py::class_<Aggressor>(mod, "Aggressor")
        .def(py::init<int>(), py::arg("id"))
        .def_readonly("id", &Aggressor::id)
        .def("__repr__", repr_aggressor);

    // AggressorAccessPattern(size_t frequency, int amplitude,
    // std::vector<Aggressor> &aggs, size_t absolute_offset)
    py::class_<AggressorAccessPattern>(mod, "AggressorAccessPattern")
        .def(py::init<size_t, int, std::vector<Aggressor>&, size_t>(),
             py::arg("frequency"), py::arg("amplitude"), py::arg("aggressors"),
             py::arg("start_offset"))
        .def_readonly("aggressors", &AggressorAccessPattern::aggressors)
        .def_readonly("amplitude", &AggressorAccessPattern::amplitude)
        .def_readonly("frequency", &AggressorAccessPattern::frequency)
        .def_readonly("start_offset", &AggressorAccessPattern::start_offset)
        .def("__repr__", repr_aggressor_access_pattern);

    // PatternAddressMapper();
    py::class_<PatternAddressMapper>(mod, "PatternAddressMapper")
        .def(py::init<>())
        .def_property_readonly(
            "id", static_cast<std::string& (PatternAddressMapper::*) (void)>(
                      &PatternAddressMapper::get_instance_id))
        .def_readonly("aggressor_to_addr",
                      &PatternAddressMapper::aggressor_to_addr)
        .def_readonly("bank", &PatternAddressMapper::bank_no)
        .def_readonly("bit_flips", &PatternAddressMapper::bit_flips)
        .def_readonly("max_row", &PatternAddressMapper::max_row)
        .def_readonly("min_row", &PatternAddressMapper::min_row)
        .def("__repr__", repr_pattern_address_mapper);

    // HammeringPattern();
    py::class_<HammeringPattern>(mod, "HammeringPattern")
        .def(py::init<>())
        .def_readonly("id", &HammeringPattern::instance_id)
        .def_readonly("mappings", &HammeringPattern::address_mappings)
        .def_readonly("access_patterns", &HammeringPattern::agg_access_patterns)
        .def_readonly("aggressors", &HammeringPattern::aggressors)
        .def_readonly("base_period", &HammeringPattern::base_period)
        .def_readonly("max_period", &HammeringPattern::max_period)
        .def_readonly("num_refresh_intervals",
                      &HammeringPattern::num_refresh_intervals)
        .def_readonly("total_activations", &HammeringPattern::total_activations)
        .def("__repr__", repr_hammering_pattern);

    // FuzzingParameterSet(int measured_num_acts_per_ref);
    py::class_<FuzzingParameterSet>(mod, "FuzzingParameterSet")
        .def(py::init<int>(), py::arg("acts_per_t_refi"))
        .def_property_readonly("max_row", &FuzzingParameterSet::get_max_row_no)
        .def("get_random_sleep_us",
             &FuzzingParameterSet::get_random_wait_until_start_hammering_us)
        .def("randomize", &params_randomize,
             "Randomize this set's semi-dynamic parameters.")
        .def("gen_pattern", &params_gen_pattern,
             "Generate a pattern and a number of mappings from this parameter "
             "set.",
             py::arg("num_mappings") = 3)
        .def("__repr__", repr_fuzzing_parameter_set);
}

}  // namespace
