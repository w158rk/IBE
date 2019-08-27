
if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../crypto)

# add the executable

add_executable (sm9test sm9test.c)
target_link_libraries (sm9test ibe crypto ssl)
add_executable (clienttest clienttest.c)
target_link_libraries (clienttest ibe crypto ssl pthread)
add_executable (servertest servertest.c)
target_link_libraries (servertest ibe crypto ssl pthread)
# add_executable (cbctest cbctest.c)
# target_link_libraries (cbctest ibe crypto ssl)

add_executable (cryptotest crypto.c)
target_link_libraries (cryptotest ibe crypto ssl)
if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(cryptotest PUBLIC DEBUG)
endif(CMAKE_BUILD_TYPE MATCHES Debug)
