#ifndef USER__H
#define USER__H

#include<string>
#include<interface.hpp>
#include<utils.hpp>

#include<rapidjson/document.h>

#include<set>

namespace user {

    class User : public interface::IUser
    {

    public :

        User(ID* id);
        int run();

        ~User();

        GET_AND_SET(interface::IUI *, ui_ptr)
        GET_AND_SET(std::string, ip_address)
        GET_AND_SET(int, port)
        GET_AND_SET(ID*, id)
        GET_AND_SET(char *, err_sig)
        GET_AND_SET(char *, cfg_filename)
        GET_AND_SET(char *, msk_filename)
        GET_AND_SET(char *, mpk_filename)
        GET_AND_SET(interface::IComm *, comm_ptr)
        GET_AND_SET(interface::IPacket *, packet_ptr)
        GET_AND_SET(char *, sm4_key)
        GET_AND_SET(std::thread *, thread)
        GET_AND_SET(char *, msk_len_file)
        GET_AND_SET(char *, mpk_len_file)
        GET_AND_SET(long, mpk_len)
        GET_AND_SET(long, msk_len)
        GET_AND_SET(long, sk_len)
        GET_AND_SET(init::Initializer*, initializer)

        void run_get_private_key(char *server_ip, 
								int server_port,
								ID *server_id=nullptr);
        void run_send_message(char *dest_ip, 
							int dest_port,
							ID *dest_id);
        void sys_init();

        void add_client(interface::IComm *comm);
        void delete_client(interface::IComm *comm);
        void add_thread(std::thread *thread);
        void delete_thread(std::thread *thread);
        void sys_setup();
        void sys_generate();
        void send_init_message_1(char *buff, int length, ID *id);
        void send_init_message_2(char *buff, int length, int, ID *id);
        void send_init_message_3(char *buff, int length, ID *id);

    private :
        DECLARE_MEMBER(interface::IUI *, ui_ptr)
        DECLARE_MEMBER(interface::IComm *, comm_ptr)
        DECLARE_MEMBER(interface::IPacket *, packet_ptr)
        DECLARE_MEMBER(std::string, ip_address)
        DECLARE_MEMBER(int, port)
        DECLARE_MEMBER(ID*, id)
        DECLARE_MEMBER(char *, err_sig)
        DECLARE_MEMBER(char *, sm4_key)
        DECLARE_MEMBER(std::thread *, thread)
        DECLARE_MEMBER(long, sk_len)
        DECLARE_MEMBER(init::Initializer*, initializer)

        // files
        DECLARE_MEMBER(char *, msk_filename)
        DECLARE_MEMBER(char *, mpk_filename)
        DECLARE_MEMBER(char *, cfg_filename)
        DECLARE_MEMBER(char *, msk_len_file)
        DECLARE_MEMBER(char *, mpk_len_file)
        DECLARE_MEMBER(long, mpk_len)
        DECLARE_MEMBER(long, msk_len)

        // with no flag with them as they are only used by the object itself
        std::set<interface::IComm *> client_comms;
        std::set<interface::IPacket *> client_packets;
        std::set<std::thread *> client_threads;

        void socket_main();
        void file_main();

    };

    class UserException : RootException 
    {
    public:
        UserException(std::string message)
        {
            set_message(message);
        }
        UserException() = default;
        ~UserException() = default;

        GET_AND_SET(std::string, message)
        std::string what(){
            if(m_fmessage)
            {
                std::string rtn("error in user module : ");
                rtn.append(m_message);
                return rtn;
            }
            return std::string("error in user module");
        }
    private: 
        DECLARE_MEMBER(std::string, message)
    };

};

void bind_objects(interface::IUser* user, 
                    interface::IComm* comm, 
                    interface::IPacket* packet, 
                    interface::IUI* uinterface,
                    char *err_sig);
void add_other_cfg(user::User& user, rapidjson::Document *doc);

#endif