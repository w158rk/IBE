/**
 * @file utils.h 
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief util macros
 */
#ifndef UTILS_H
#define UTILS_H

// #define ERROR(info) fprintf(stderr, "[%s:%d]%s\n    %s\n", __FILE__, \
//                 __LINE__, __func__, info) 
#define ERROR(info)


#define GET_AND_SET(type, name) \
    void set_##name(type name); \
    void unset_##name(); \
    type get_##name();

#define GET_AND_SET_IMPL(cls, type, name) \
    void cls::set_##name(type name){ \
        m_f##name = true;       \
        m_##name = name;        \
    }\
    void cls::unset_##name(){ \
        m_f##name = false;       \
    }\
    type cls::get_##name(){\
        if(!m_f##name){ \
            ERROR("some members not set");\
        }   \
        return m_##name;    \
    }


#define VIRTUAL_GET_AND_SET(type, name) \
    virtual void set_##name(type name) = 0; \
    virtual void unset_##name() = 0; \
    virtual type get_##name() = 0;

#define DECLARE_MEMBER(type, name) \
    type m_##name;          \
    bool m_f##name = false;

#define GENERATE_SK_FILENAME(client_id) \
    int filename_len = client_id->length + 9;    \
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