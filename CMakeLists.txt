cmake_minimum_required(VERSION 3.18)
project(mapdump CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# Dobby (inline hook). الـ workflow ينزّله بـ third_party/Dobby
add_subdirectory(third_party/Dobby dobby_build)

add_library(mapdump SHARED src/mapdump.cpp)
target_include_directories(mapdump PRIVATE third_party/Dobby/include)
target_link_libraries(mapdump PRIVATE dobby_static log)
