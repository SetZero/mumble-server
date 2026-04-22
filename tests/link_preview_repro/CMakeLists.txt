cmake_minimum_required(VERSION 3.16)
project(link_preview_repro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network)

add_executable(link_preview_repro main.cpp)
target_link_libraries(link_preview_repro PRIVATE Qt6::Core Qt6::Network)
