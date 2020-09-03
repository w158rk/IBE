
if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../gmcrypto)  #链接库在../crypto中

# add the executable

# add_executable (sm9test sm9test.c)  #添加可执行文件sm9test.c生成sm9test
# target_link_libraries (sm9test ibe gmcrypto pthread)  #将sm9test与ibe，ctypto，ssl库文件链接
# add_executable (clienttest clienttest.cpp)    #添加可执行文件clienttest.c生成clienttest
# target_link_libraries (clienttest ibe gmcrypto pthread)   #与库文件链接
# add_executable (usertest usertest.cpp)    #添加可执行文件usertest.c生成usertest
# target_link_libraries (usertest ibe gmcrypto pthread)   #与库文件链接
# add_executable (id2pointtest id2pointtest.c)
# target_link_libraries (id2pointtest ibe gmcrypto pthread)

add_executable (sstest sstest.c)
target_link_libraries (sstest ibe gmcrypto pthread)

# add_executable (cryptotest gmcrypto.c)    #添加可执行文件crypto.c生成cryptotest
# target_link_libraries (cryptotest ibe gmcrypto pthread)   #与库文件链接
add_executable(sm4test sm4test.c)
target_link_libraries(sm4test ibe gmcrypto pthread)
add_executable(smxtest smxtest.c)
target_link_libraries(smxtest ibe gmcrypto pthread)
