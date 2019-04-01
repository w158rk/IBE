
SET(PROJECT_INCLUDE_DIR ../include)

link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library)

include_directories (${PROJECT_INCLUDE_DIR} ../IBE)

# add the executable
add_executable (app main.c)
add_executable (setup setup.c)
add_executable (encrypt encrypt.c)
add_executable (extract extract.c)
add_executable (decrypt decrypt.c)

target_link_libraries (app ibe pbc gmp)
target_link_libraries (setup ibe pbc gmp)
target_link_libraries (encrypt ibe pbc gmp)
target_link_libraries (extract ibe pbc gmp)
target_link_libraries (decrypt ibe pbc gmp)