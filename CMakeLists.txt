cmake_minimum_required(VERSION 2.6)

project(antiblock)

add_subdirectory(hashmap)

include_directories(include hashmap/include) 
add_executable(antiblock antiblock.c dns_ans.c hash.c net_data.c route.c stat.c ttl_check.c urls_read.c)

target_link_libraries(antiblock hashmap curl)

install(TARGETS hashmap RUNTIME DESTINATION /usr/bin/)
