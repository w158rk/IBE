
SET(PROJECT_INCLUDE_DIR ../include)

if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../IBE)

# add the executable
add_executable (app main.c)
add_executable (init init.c)
add_executable (encrypt encrypt.c)
add_executable (extract extract.c)
add_executable (decrypt decrypt.c)
target_link_libraries (app ibe pbc gmp)
target_link_libraries (init ibe pbc gmp)
target_link_libraries (encrypt ibe pbc gmp)
target_link_libraries (extract ibe pbc gmp)
target_link_libraries (decrypt ibe pbc gmp)

add_executable (encrypt_aes encrypt_aes.c)
target_link_libraries (encrypt_aes tiny-aes)

add_executable (decrypt_aes decrypt_aes.c)
target_link_libraries (decrypt_aes tiny-aes)
