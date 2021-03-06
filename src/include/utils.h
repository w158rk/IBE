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
// #define ERROR(info)


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
            ERROR("some members not set, return NULL");\
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

#define GET_AND_SET2(type1, type2, name) \
    void set_##name(type1, type2 name); \
    void unset_##name(); \
    type1, type2 get_##name();

// return the reference
#define GET_AND_SET_IMPL2(cls, type1, type2, name) \
    void cls::set_##name(type1, type2 name){ \
        m_f##name = true;       \
        m_##name = name;        \
    }\
    void cls::unset_##name(){ \
        m_f##name = false;       \
    }\
    type1, type2 cls::get_##name(){\
        if(!m_f##name){ \
            ERROR("some members not set");\
        }   \
        return m_##name;    \
    }

#define VIRTUAL_GET_AND_SET2(type1, type2, name) \
    virtual void set_##name(type1, type2 name) = 0; \
    virtual void unset_##name() = 0; \
    virtual type1, type2 get_##name() = 0;

#define DECLARE_MEMBER2(type1, type2, name) \
    type1, type2 m_##name;          \
    bool m_f##name = false;

#define GENERATE_DOMAIN_SK_FILENAME(client_id) \
    int domain_filename_len = client_id->length + 16;    \
    char *domain_filename = (char *)malloc(domain_filename_len);  \
    domain_filename[0] = 's';      \
    domain_filename[1] = 'k';\
    domain_filename[2] = '-';\
    domain_filename[3] = 'd';\
    domain_filename[4] = 'o';\
    domain_filename[5] = 'm';\
    domain_filename[6] = 'a';\
    domain_filename[7] = 'i';\
    domain_filename[8] = 'n';\
    domain_filename[9] = '_';\
    memcpy(domain_filename+10, (client_id->id), (client_id->length));\
    domain_filename[domain_filename_len-6] = '.'; \
    domain_filename[domain_filename_len-5] = 'c'; \
    domain_filename[domain_filename_len-4] = 'o'; \
    domain_filename[domain_filename_len-3] = 'n'; \
    domain_filename[domain_filename_len-2] = 'f';\
    domain_filename[domain_filename_len-1] = '\0';

#define FREE_DOMAIN_SK_FILENAME free(domain_filename);

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

#define FREE_SK_FILENAME free(filename);


#define GENERATE_SK_LEN_FILENAME(client_id) \
    int filename_len = client_id->length + 13;    \
    char *filename = (char *)malloc(filename_len);  \
    filename[0] = 's';      \
    filename[1] = 'k';\
    filename[2] = '-';\
    filename[3] = 'l';\
    filename[4] = 'e';\
    filename[5] = 'n';\
    filename[6] = '_';\
    memcpy(filename+7, (client_id->id), (client_id->length));\
    filename[filename_len-6] = '.'; \
    filename[filename_len-5] = 'c'; \
    filename[filename_len-4] = 'o'; \
    filename[filename_len-3] = 'n'; \
    filename[filename_len-2] = 'f';\
    filename[filename_len-1] = '\0';
#define FREE_SK_LEN_FILENAME free(filename);

#define GENERATE_SKLEN_FILENAME(id, id_len) \
    int filename_len = id_len + 13;    \
    char *filename = (char *)malloc(filename_len);  \
    filename[0] = 's';      \
    filename[1] = 'k';\
    filename[2] = '-';\
    filename[3] = 'l';\
    filename[4] = 'e';\
    filename[5] = 'n';\
    filename[6] = '_';\
    memcpy(filename+7, id, id_len);\
    filename[filename_len-6] = '.'; \
    filename[filename_len-5] = 'c'; \
    filename[filename_len-4] = 'o'; \
    filename[filename_len-3] = 'n'; \
    filename[filename_len-2] = 'f';\
    filename[filename_len-1] = '\0';
#define FREE_SKLEN_FILENAME free(filename);


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

#define GENERATE_MPK_FILENAME(id, id_len) \
    int mpk_filename_len = id_len + 9;    \
    char *mpk_filename = (char *)malloc(mpk_filename_len);  \
    mpk_filename[0] = 'm';      \
    mpk_filename[1] = 'p';\
    mpk_filename[2] = 'k';\
    memcpy(mpk_filename+3, id, id_len);\
    mpk_filename[mpk_filename_len-6] = '.'; \
    mpk_filename[mpk_filename_len-5] = 'c'; \
    mpk_filename[mpk_filename_len-4] = 'o'; \
    mpk_filename[mpk_filename_len-3] = 'n'; \
    mpk_filename[mpk_filename_len-2] = 'f';\
    mpk_filename[mpk_filename_len-1] = '\0';

#define FREE_MPK_FILENAME free(mpk_filename)

#define GENERATE_MPK2_FILENAME(id, id_len) \
    int mpk2_filename_len = id_len + 9;    \
    char *mpk2_filename = (char *)malloc(mpk2_filename_len);  \
    mpk2_filename[0] = 'm';      \
    mpk2_filename[1] = 'p';\
    mpk2_filename[2] = 'k';\
    memcpy(mpk2_filename+3, id, id_len);\
    mpk2_filename[mpk2_filename_len-6] = '.'; \
    mpk2_filename[mpk2_filename_len-5] = 'c'; \
    mpk2_filename[mpk2_filename_len-4] = 'o'; \
    mpk2_filename[mpk2_filename_len-3] = 'n'; \
    mpk2_filename[mpk2_filename_len-2] = 'f';\
    mpk2_filename[mpk2_filename_len-1] = '\0';

#define FREE_MPK2_FILENAME free(mpk2_filename)

#define GENERATE_SIGN_FILENAME(id, id_len) \
    int filename_sign_len = id_len + 11;    \
    char *filename_sign = (char *)malloc(filename_sign_len);  \
    filename_sign[0] = 's';      \
    filename_sign[1] = 'i';\
    filename_sign[2] = 'g';\
    filename_sign[3] = 'n';\
    filename_sign[4] = '_';\
    memcpy(filename_sign+5, id, id_len);\
    filename_sign[filename_sign_len-6] = '.'; \
    filename_sign[filename_sign_len-5] = 'c'; \
    filename_sign[filename_sign_len-4] = 'o'; \
    filename_sign[filename_sign_len-3] = 'n'; \
    filename_sign[filename_sign_len-2] = 'f';\
    filename_sign[filename_sign_len-1] = '\0';

#define FREE_SIGN_FILENAME free(filename_sign)

#define GENERATE_SIGN_LEN_FILENAME(id, id_len) \
    int signlen = id_len + 15;    \
    char *filename_len_sign = (char *)malloc(signlen);  \
    filename_len_sign[0] = 's';      \
    filename_len_sign[1] = 'i';\
    filename_len_sign[2] = 'g';\
    filename_len_sign[3] = 'n';\
    filename_len_sign[4] = '-';\
    filename_len_sign[5] = 'l';\
    filename_len_sign[6] = 'e';\
    filename_len_sign[7] = 'n';\
    filename_len_sign[8] = '_';\
    memcpy(filename_len_sign+9, id, id_len);\
    filename_len_sign[signlen-6] = '.'; \
    filename_len_sign[signlen-5] = 'c'; \
    filename_len_sign[signlen-4] = 'o'; \
    filename_len_sign[signlen-3] = 'n'; \
    filename_len_sign[signlen-2] = 'f';\
    filename_len_sign[signlen-1] = '\0';

#define FREE_SIGN_LEN_FILENAME free(filename_len_sign)

#define GENERATE_INTKEY_FILENAME(id, id_len) \
    int intkeylen = id_len + 13;    \
    char *filename_key = (char *)malloc(intkeylen);  \
    filename_key[0] = 'i';      \
    filename_key[1] = 'n';\
    filename_key[2] = 't';\
    filename_key[3] = 'k';\
    filename_key[4] = 'e';\
    filename_key[5] = 'y';\
    filename_key[6] = '-';\
    memcpy(filename_key+7, id, id_len);\
    filename_key[intkeylen-6] = '.'; \
    filename_key[intkeylen-5] = 'c'; \
    filename_key[intkeylen-4] = 'o'; \
    filename_key[intkeylen-3] = 'n'; \
    filename_key[intkeylen-2] = 'f';\
    filename_key[intkeylen-1] = '\0';

#define FREE_INTKEY_FILENAME free(filename_key)

#define GENERATE_IOTKEY_FILENAME(id, id_len) \
    int iotkeylen = id_len + 13;    \
    char *filename_key = (char *)malloc(iotkeylen);  \
    filename_key[0] = 'i';      \
    filename_key[1] = 'o';\
    filename_key[2] = 't';\
    filename_key[3] = 'k';\
    filename_key[4] = 'e';\
    filename_key[5] = 'y';\
    filename_key[6] = '-';\
    memcpy(filename_key+7, id, id_len);\
    filename_key[iotkeylen-6] = '.'; \
    filename_key[iotkeylen-5] = 'c'; \
    filename_key[iotkeylen-4] = 'o'; \
    filename_key[iotkeylen-3] = 'n'; \
    filename_key[iotkeylen-2] = 'f';\
    filename_key[iotkeylen-1] = '\0';

#define FREE_IOTKEY_FILENAME free(filename_key)


#ifdef __cplusplus 
extern "C" {
#endif

/**
 * @brief set the first 4 bytes of the ptr as the val 
 */
void set_int(char *ptr, int val);
/**
 * @brief get the first 4 bytes of the ptr as the val 
 */
void get_int(char *ptr, int *val);

#ifdef __cplusplus
}
#endif

#endif