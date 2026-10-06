cmake_minimum_required(VERSION 3.13)
project(
    antiblock
    VERSION 3.0.0
    LANGUAGES C)

find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap development files are required")
endif()

add_executable(
    antiblock
    src/main.c
    src/config.c
    src/domains.c
    src/dns.c
    src/capture.c
    src/routes.c
    src/telemetry.c
    hashmap/src/array_hashmap.c)

target_include_directories(antiblock PRIVATE include hashmap/include
                                             ${PCAP_INCLUDE_DIR})

target_compile_options(antiblock PRIVATE -std=gnu99 -Wall -Wextra -Werror
                                         -Wpedantic)

target_link_libraries(antiblock PRIVATE curl ${PCAP_LIBRARY})

if(CMAKE_BUILD_TYPE STREQUAL "Debug_ASan")
    target_compile_options(antiblock PRIVATE -Og -g -fsanitize=address
                                             -fno-omit-frame-pointer)
    target_link_options(antiblock PRIVATE -g -fsanitize=address)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug_MSan")
    target_compile_options(antiblock PRIVATE -Og -g -fsanitize=memory
                                             -fno-omit-frame-pointer)
    target_link_options(antiblock PRIVATE -g -fsanitize=memory)
endif()

install(TARGETS antiblock DESTINATION bin)
