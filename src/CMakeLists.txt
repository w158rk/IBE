#设置可执行文件

aux_source_directory(./comm TEMP_SRC)   #将./comm目录下的所有源文件赋值为TEMP_SRC
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./crypto TEMP_SRC) #添加./crypto目录下的源文件
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./packet TEMP_SRC) #添加.packet目录下的源文件
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./ss TEMP_SRC)
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./init TEMP_SRC)
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./sys TEMP_SRC)    #添加./sys目录下的源文件
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./ui TEMP_SRC)    #添加./sys目录下的源文件
SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./user TEMP_SRC)    #添加./sys目录下的源文件
SET (MY_SRC ${TEMP_SRC})

add_library(ibe ${MY_SRC})  #指定编译包含的源文件{MY_SRC}中的，生成ibe
if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(ibe PUBLIC DEBUG)
endif(CMAKE_BUILD_TYPE MATCHES Debug)
