
cmake_minimum_required (VERSION 2.6)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_CXX_COMPILER g++)#设置C++编译器

project (RPO_IBE)

#设置库
# SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/lib)
if(NOT DEFINED ENV{IBE_LIB})
    message(FATAL_ERROR "not defined environment variable:IBE_LIB")  
endif()

# export IBE_LIB={GmSSL/build}
SET(PROJECT_LIB_DIR $ENV{IBE_LIB})    #定义一个变量PROJECT_LIB_DIR，变量的值为ENV{IBE_LIB}
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin) #定义一个变量CMAKE_RUNTIME_OUTPUT_DIRECTORY，变量的值为/bin
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib) #定义一个变量CMAKE_RUNTIME_OUTPUT_DIRECTORY，变量的值为/bin

link_directories(${PROJECT_LIB_DIR})    #连接库PROJECT_LIB_DIR，即/src/lib
include_directories(${CMAKE_SOURCE_DIR}/src/include)    #添加需要的头文件/src/include

if(CMAKE_BUILD_TYPE MATCHES Debug)
    SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} )
    SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} )
    SET(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} )
    add_compile_options(${CMAKE_CXX_FLAGS})
else(CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_options(-O3)
endif(CMAKE_BUILD_TYPE MATCHES Debug)
# add_subdirectory (${CMAKE_SOURCE_DIR}/src/IBE)
#指明本项目包含的子目录CMakeLists文件其他的位置有/src和/src/test 
add_subdirectory (${CMAKE_SOURCE_DIR}/src)   
add_subdirectory (${CMAKE_SOURCE_DIR}/src/test) 

