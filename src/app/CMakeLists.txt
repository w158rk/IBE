
cmake_minimum_required (VERSION 2.6)
project (IBE)

# configure a header file to pass some of the CMake settings
# to the source code
# configure_file (
#   "${PROJECT_SOURCE_DIR}/TutorialConfig.h.in"
#   "${PROJECT_BINARY_DIR}/TutorialConfig.h"
#   )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
# include_directories("${PROJECT_BINARY_DIR}")
SET(PROJECT_INCLUDE_DIR ../include)

link_directories(${PROJECT_LIB_DIR}  ../IBE )

include_directories (${PROJECT_INCLUDE_DIR} ../IBE)

# add the executable
add_executable (app main.c)
target_link_libraries (app ibe pbc gmp)