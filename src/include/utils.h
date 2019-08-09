/**
 * @file utils.h 
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief util macros
 */


#define ERROR(info) fprintf(stderr, "[%s:%d]%s\n    %s\n", __FILE__, \
                __LINE__, __func__, info) 
