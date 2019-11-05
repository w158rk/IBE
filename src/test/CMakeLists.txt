
if(WIN32)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/WIN32)
endif(WIN32)

if(UNIX)
    link_directories(${CMAKE_SOURCE_DIR}/src/IBE ${CMAKE_SOURCE_DIR}/src/Library/UNIX)
endif(UNIX)

include_directories (${PROJECT_INCLUDE_DIR} ../crypto)  #链接库在../crypto中

# add the executable

# add_executable (sm9test sm9test.c)  #添加可执行文件sm9test.c生成sm9test
# target_link_libraries (sm9test ibe ssl crypto pthread)  #将sm9test与ibe，ctypto，ssl库文件链接
add_executable (clienttest clienttest.cpp)    #添加可执行文件clienttest.c生成clienttest
target_link_libraries (clienttest ibe ssl crypto pthread)   #与库文件链接
add_executable (servertest servertest.cpp)    #添加可执行文件servertest.c生成servertest
target_link_libraries (servertest ibe ssl crypto pthread)   #与库文件链接
add_executable (id2pointtest id2pointtest.c)
target_link_libraries (id2pointtest ibe ssl crypto pthread)

# add_executable (cryptotest crypto.c)    #添加可执行文件crypto.c生成cryptotest
# target_link_libraries (cryptotest ibe ssl crypto pthread)   #与库文件链接
add_executable(sm4test sm4test.c)
target_link_libraries(sm4test ibe ssl crypto pthread)
