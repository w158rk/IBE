if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../crypto)  #链接库在../crypto中

# add the executable

add_executable (init-client init-client.cpp)
target_link_libraries (init-client ibe ssl crypto pthread)

add_executable (init-server init-server.cpp)
target_link_libraries (init-server ibe ssl crypto pthread)