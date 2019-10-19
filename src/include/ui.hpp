#include<interface.hpp>
#include<utils.h>

namespace ui {
    class UInterface : public interface::IUI 
    {
    public:
        UInterface();
        ~UInterface() = default;
        void run();

        GET_AND_SET(interface::IUser * , user_ptr)

    private:
        DECLARE_MEMBER(interface::IUser * , user_ptr)

        int socket_interface_run();

    };
}