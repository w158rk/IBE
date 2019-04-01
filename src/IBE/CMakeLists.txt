
cmake_minimum_required (VERSION 2.6)

SET(PROJECT_INCLUDE_DIR ../include)

SET(PROJECT_LIB_DIR ${PROJECT_BINARY_DIR}/include)
link_directories(${PROJECT_LIB_DIR})

include_directories (${PROJECT_INCLUDE_DIR})

# add the executable
aux_source_directory(. DIR_SRCS)
add_library(ibe ${DIR_SRCS})
# target_link_libraries (app gmp pbc)