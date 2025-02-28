cmake_minimum_required(VERSION 3.13)

project(antiblock)

add_compile_options(-Wall -Wextra -Werror -Wpedantic -DTHREAD_SAFETY)
add_link_options()
include_directories(include hashmap/include)

add_subdirectory(hashmap)

if(CMAKE_BUILD_TYPE MATCHES "Debug_ASan")
    add_compile_options(-Og -g -fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=address)
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug_MSan")
    add_compile_options(-Og -g -fsanitize=memory -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=memory)
endif()

file(GLOB SRC "src/*.c")
add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} hashmap curl pcap)

install(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin)

find_program(CLANGFORMAT clang-format)
if(CLANGFORMAT)
    add_custom_command(TARGET ${PROJECT_NAME} PRE_BUILD
        COMMAND clang-format -i ${CMAKE_CURRENT_SOURCE_DIR}/include/* ${CMAKE_CURRENT_SOURCE_DIR}/src/*
    )
endif()
