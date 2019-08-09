
# aux_source_directory(./comm TEMP_SRC)
# SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./crypto TEMP_SRC)
SET (MY_SRC ${TEMP_SRC})
# aux_source_directory(./packet TEMP_SRC)
# SET (MY_SRC ${TEMP_SRC})
# aux_source_directory(./ss TEMP_SRC)
# SET (MY_SRC ${TEMP_SRC})
aux_source_directory(./sys TEMP_SRC)
SET (MY_SRC ${TEMP_SRC})

add_library(ibe ${MY_SRC})
if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(ibe PUBLIC DEBUG)
endif(CMAKE_BUILD_TYPE MATCHES Debug)


