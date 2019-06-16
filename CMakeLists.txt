
cmake_minimum_required (VERSION 2.6)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_CXX_COMPILER g++)#设置C++编译器

project (RPO_IBE)

# SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/lib)
SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/lib)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

link_directories(${PROJECT_LIB_DIR})
include_directories(${CMAKE_SOURCE_DIR}/src/include)

# add_subdirectory (${CMAKE_SOURCE_DIR}/src/IBE) 
add_subdirectory (${CMAKE_SOURCE_DIR}/src/crypto) 
add_subdirectory (${CMAKE_SOURCE_DIR}/src/test) 
add_subdirectory (${CMAKE_SOURCE_DIR}/src/comm) 