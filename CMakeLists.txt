
cmake_minimum_required (VERSION 2.6)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_CXX_COMPILER g++)#设置C++编译器

project (RPO_IBE)

#设置库
# SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/lib)
SET(PROJECT_LIB_DIR ${CMAKE_SOURCE_DIR}/src/lib)    #定义一个变量PROJECT_LIB_DIR，变量的值为/src/lib
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin) #定义一个变量CMAKE_RUNTIME_OUTPUT_DIRECTORY，变量的值为/bin

link_directories(${PROJECT_LIB_DIR})    #连接库PROJECT_LIB_DIR，即/src/lib
include_directories(${CMAKE_SOURCE_DIR}/src/include)    #添加需要的头文件/src/include

if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_options(-g)
endif(CMAKE_BUILD_TYPE MATCHES Debug)
# add_subdirectory (${CMAKE_SOURCE_DIR}/src/IBE)
#指明本项目包含的子目录CMakeLists文件其他的位置有/src和/src/test 
add_subdirectory (${CMAKE_SOURCE_DIR}/src)   
add_subdirectory (${CMAKE_SOURCE_DIR}/src/test) 

