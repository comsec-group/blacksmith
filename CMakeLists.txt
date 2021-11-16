cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

# === OPTIONS ==================================================================

set(
        BLACKSMITH_ENABLE_JSON
        ON
        CACHE BOOL
        "Use the nlohmann/json library to export JSON-formatted fuzzing data."
        FORCE
)

set(
        BLACKSMITH_ENABLE_JITTING
        ON
        CACHE BOOL
        "Use the asmjit library to jit the hammering code."
        FORCE
)

set(
        BLACKSMITH_ENABLE_PYBIND
        ON
        CACHE BOOL
        "Generate pybind11 Python bindings."
        FORCE
)

string(ASCII 27 ESC)

# === DEFINITIONS ==============================================================

set(GIT_COMMIT_HASH "NO_REPOSITORY")

execute_process(
        COMMAND git status
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE ret
        OUTPUT_QUIET
        ERROR_QUIET
)

if (ret EQUAL "0")
    # We're in a git repository, attempt to retrieve the current commit tag.
    execute_process(
            COMMAND git rev-parse HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif ()

# === DEPENDENCIES =============================================================

if(BLACKSMITH_ENABLE_PYBIND)
    # Makes redistribution easier.
    set(ASMJIT_STATIC TRUE)
endif()

add_subdirectory(external)

# === LIBBLACKSMITH ============================================================

add_library(
        bs
        include/GlobalDefines.hpp
        include/Utilities/TimeHelper.hpp
        src/Forges/FuzzyHammerer.cpp
        src/Forges/ReplayingHammerer.cpp
        src/Forges/TraditionalHammerer.cpp
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp
        src/Fuzzer/CodeJitter.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/PatternAddressMapper.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/Memory/DRAMAddr.cpp
        src/Memory/DramAnalyzer.cpp
        src/Memory/Memory.cpp
        src/Utilities/Enums.cpp
        src/Utilities/Logger.cpp
)

target_include_directories(
        bs
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Note: PUBLIC to also force consumers (i.e., the blacksmith executable) to use
# these features and options.
target_compile_features(
        bs
        PUBLIC
        cxx_std_17
)

target_compile_options(
        bs
        PUBLIC
        -O0
        -Wall
        -Wextra
        -Wno-unused-function
        -Wno-format-security
)

if (BLACKSMITH_ENABLE_JSON)
    target_link_libraries(
            bs
            PUBLIC
            nlohmann_json::nlohmann_json
    )

    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JSON
    )
endif ()

if (BLACKSMITH_ENABLE_JITTING)
    # This fixes an issue that causes GCC 10.3 (but not 8.3 or 11.1) to miss a
    # header somehow.
    FetchContent_MakeAvailable(asmjit)

    target_include_directories(
            bs
            PUBLIC
            ${asmjit_SOURCE_DIR}/src
    )

    target_link_libraries(
            bs
            PRIVATE
            asmjit
    )

    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JITTING
    )
endif ()

if (BLACKSMITH_ENABLE_PYBIND)
    pybind11_add_module(
            pyblacksmith
            src/Bindings.cpp
    )

    target_link_libraries(
            pyblacksmith
            PRIVATE
            bs
    )

    set_target_properties(
            pyblacksmith
            PROPERTIES
            OUTPUT_NAME
            _blacksmith
    )

    target_compile_options(
            asmjit
            PRIVATE
            -fPIC
    )

    target_compile_options(
            bs
            PRIVATE
            -fPIC
    )

    if (BLACKSMITH_ENABLE_JITTING)
        target_link_libraries(
                pyblacksmith
                PRIVATE
                asmjit
        )
    endif()
endif()

# === BLACKSMITH ===============================================================

add_executable(
        blacksmith
        include/Blacksmith.hpp
        src/Blacksmith.cpp
)

target_compile_definitions(
        blacksmith
        PRIVATE
        GIT_COMMIT_HASH="${GIT_COMMIT_HASH}"
)

target_link_libraries(
        blacksmith
        PRIVATE
        bs
        argagg
)

# === CLEANUP ==================================================================

unset(BLACKSMITH_ENABLE_JSON CACHE)
unset(BLACKSMITH_ENABLE_JITTING CACHE)
