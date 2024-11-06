cmake_minimum_required(VERSION 3.10)

project(CloudiskServer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(include)
file(GLOB SOURCES "src/*.cc")

add_executable(CloudiskServer ${SOURCES} main.cc)

link_directories("usr/local/lib64")
target_link_libraries(CloudiskServer wfrest workflow crypt crypto)