cmake_minimum_required(VERSION 3.16)
project(IDPS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_library(SECCOMP_LIB seccomp REQUIRED)
find_library(GTEST_LIB gtest REQUIRED)
find_library(GTEST_MAIN_LIB gtest_main REQUIRED)

# 소스 파일 (main.cpp 제외)
file(GLOB_RECURSE LIB_SOURCES
    "src/ids/*.cpp"
    "src/control/*.cpp"
    "src/sandbox/*.cpp"
)

# 메인 실행 파일
add_executable(idps src/main.cpp ${LIB_SOURCES})
target_link_libraries(idps
    Threads::Threads
    ${PCAP_LIB}
    ${SQLITE3_LIB}
    ${SECCOMP_LIB}
    nlohmann_json::nlohmann_json
)

# 테스트 실행 파일
file(GLOB TEST_SOURCES "tests/*.cpp")
add_executable(idps_test ${TEST_SOURCES} ${LIB_SOURCES})
target_include_directories(idps_test PRIVATE src)
target_link_libraries(idps_test
    Threads::Threads
    ${PCAP_LIB}
    ${SQLITE3_LIB}
    ${SECCOMP_LIB}
    nlohmann_json::nlohmann_json
    ${GTEST_LIB}
    ${GTEST_MAIN_LIB}
)

target_compile_options(idps PRIVATE -Wall -Wextra)
target_compile_options(idps_test PRIVATE -Wall -Wextra)

enable_testing()
add_test(NAME idps_test COMMAND idps_test)
