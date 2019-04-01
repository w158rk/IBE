
cmake_minimum_required (VERSION 2.6)

SET(CMAKE_C_COMPILER gcc)
# SET(CMAKE_CXX_COMPILER g++)#设置C++编译器
project (IBE)

SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/Library)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

link_directories(${PROJECT_LIB_DIR})

add_subdirectory (src/IBE) 
add_subdirectory (src/app) 
 