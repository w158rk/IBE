#include<interface.hpp>
#include<utils.h>

namespace ui {
    class UInterface : public interface::IUI 
    {
    public:
        UInterface() = default;
        ~UInterface() = default;
        void run();
        void print(std::string message);
        void error(std::string message);
        void print(char *message, int length);
        void error(char *message, int length);

        GET_AND_SET(interface::IUser * , user_ptr)

    private:
        DECLARE_MEMBER(interface::IUser * , user_ptr)

        int socket_interface_run();

    };
}