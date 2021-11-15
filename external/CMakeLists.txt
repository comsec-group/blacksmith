include(FetchContent)

function(message)
    if (NOT MESSAGE_QUIET)
        _message(${ARGN})
    endif()
endfunction()

# === ARGAGG ===================================================================

# this is to silence the CMake warning "Policy CMP0048 is not set: project() command manages VERSION variables."
# because argagg does not set the project() infos properly
set(CMAKE_PROJECT_INCLUDE_BEFORE "${CMAKE_CURRENT_SOURCE_DIR}/EnableCMP0048.cmake")

message(STATUS "Fetching external dependency argagg")
set(MESSAGE_QUIET ON)

FetchContent_Declare(
        argagg
        GIT_REPOSITORY https://github.com/vietjtnguyen/argagg.git
        GIT_TAG 79e4adfa2c6e2bfbe63da05cc668eb9ad5596748
)

FetchContent_MakeAvailable(argagg)

# This is a header-only library, and the provided CMakeLists.txt does not
# provide a suitable library target.
add_library(
        argagg
        INTERFACE
)

target_include_directories(
        argagg
        INTERFACE
        ${argagg_SOURCE_DIR}/include
)

unset(CMAKE_PROJECT_INCLUDE_BEFORE)

message(STATUS "Fetching external dependency argagg -- done!")
set(MESSAGE_QUIET OFF)

# === ASMJIT ===================================================================

if (BLACKSMITH_ENABLE_JITTING)
    message(STATUS "Fetching external dependency asmjit")
    set(MESSAGE_QUIET OFF)

    FetchContent_Declare(
            asmjit
            GIT_REPOSITORY https://github.com/asmjit/asmjit.git
            GIT_TAG 78de7d9c81a6ad1b0f732b52666960d9be1c6461
    )

    FetchContent_MakeAvailable(asmjit)

    set(MESSAGE_QUIET OFF)
    message(STATUS "Fetching external dependency asmjit -- done!")
endif()

# === NLOHMANN/JSON ============================================================

if (BLACKSMITH_ENABLE_JSON)
    message(STATUS "Fetching external dependency nlohmann/json")
    set(MESSAGE_QUIET ON)

    FetchContent_Declare(
            json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.9.1
    )

    FetchContent_GetProperties(json)
    if (NOT json_POPULATED)
        FetchContent_Populate(json)
        add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif ()

    set(MESSAGE_QUIET OFF)
    message(STATUS "Fetching external dependency nlohmann/json -- done!")
endif()
