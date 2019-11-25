#include<interface.hpp>
#include<utils.h>

namespace ui {
    class UInterface : public interface::IUI 
    {
    public:
        UInterface() = default;
        ~UInterface() = default;
        void run();

        GET_AND_SET(user::User * , user_ptr)

    private:
        DECLARE_MEMBER(user::User * , user_ptr)

        int socket_interface_run();

    };
}