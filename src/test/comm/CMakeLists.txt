
if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../crypto)

# add the executable
add_executable (servertest servertest.c)
target_link_libraries (servertest commapi cryptoapi crypto ssl pthread)
add_executable (clienttest clienttest.c)
target_link_libraries (clienttest commapi cryptoapi crypto ssl pthread)
