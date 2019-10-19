/**
 * @file utils.h 
 * @author Wang Ruikai 
 * @date August 7th, 2019 
 * @brief util macros
 */


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
