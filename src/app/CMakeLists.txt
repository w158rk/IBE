
SET(PROJECT_INCLUDE_DIR ../include)

link_directories(${CMAKE_SOURCE_DIR}/IBE ${CMAKE_SOURCE_DIR}/Library)

include_directories (${PROJECT_INCLUDE_DIR} ../IBE)

# add the executable
add_executable (setup setup.c)
# add_executable (app main.c)
# add_executable (app main.c)
target_link_libraries (setup ibe pbc gmp)