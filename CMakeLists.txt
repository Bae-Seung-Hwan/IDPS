cmake_minimum_required(VERSION 3.16)
project(IDPS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_library(SECCOMP_LIB seccomp REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(idps ${SOURCES})

target_link_libraries(idps
    Threads::Threads
    ${PCAP_LIB}
    ${SQLITE3_LIB}
    ${SECCOMP_LIB}
    nlohmann_json::nlohmann_json
)

target_compile_options(idps PRIVATE -Wall -Wextra)