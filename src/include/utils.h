/**
 * @file utils.h 
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief util macros
 */
#ifndef UTILS_H
#define UTILS_H

#define ERROR(info) fprintf(stderr, "[%s:%d]%s\n    %s\n", __FILE__, \
                __LINE__, __func__, info) 



#define GET_AND_SET(type, name) \
    void set_##name(type name){ \
        m_##name = name;        \
        m_f##name = true;       \
    }\
    type get_##name(){\
        if(!m_f##name){ \
            ERROR("some members not set");\
        }   \
        return m_##name;    \
    }

#define DECLARE_MEMBER(type, name) \
    type m_##name;          \
    bool m_f##name = false;

#define GENERATE_SK_FILENAME(client_id) \
    int filename_len = ctx->dest_id->length + 9;    \
    char *filename = (char *)malloc(filename_len);  \
    filename[0] = 's';      \
    filename[1] = 'k';\
    filename[2] = '_';\
    memcpy(filename+3, (client_id->id), (client_id->length));\
    filename[filename_len-6] = '.'; \
    filename[filename_len-5] = 'c'; \
    filename[filename_len-4] = 'o'; \
    filename[filename_len-3] = 'n'; \
    filename[filename_len-2] = 'f';\
    filename[filename_len-1] = '\0';

#define FREE_SK_FILENAME free(filename)

#define GENERATE_SM4_FILENAME(id, id_len) \
    int filename_len = id_len + 10;    \
    char *filename = (char *)malloc(filename_len);  \
    filename[0] = 's';      \
    filename[1] = 'm';\
    filename[2] = '4';\
    filename[3] = '_';\
    memcpy(filename+4, id, id_len);\
    filename[filename_len-6] = '.'; \
    filename[filename_len-5] = 'c'; \
    filename[filename_len-4] = 'o'; \
    filename[filename_len-3] = 'n'; \
    filename[filename_len-2] = 'f';\
    filename[filename_len-1] = '\0';

#define FREE_SM4_FILENAME free(filename)

#endif