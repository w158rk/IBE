
if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../crypto)

# add the executable
add_executable (sm9test sm9test.c)
target_link_libraries (sm9test cryptoapi crypto ssl)
add_executable (cbctest cbctest.c)
target_link_libraries (cbctest cryptoapi crypto ssl)
