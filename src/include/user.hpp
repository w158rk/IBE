#ifndef USER__H
#define USER__H

#include<string>
#include<ds.h>
#include<interface.hpp>
#include<utils.h>

#include<rapidjson/document.h>

namespace user {

    class User : public interface::IUser
    {

    public :

        User(std::string ip_address, int port, ID* id);
        User(ID* id);
        int run();

        ~User();

        GET_AND_SET(interface::IComm *, comm_ptr)
        GET_AND_SET(interface::IPacket *, packet_ptr)
        GET_AND_SET(interface::IUI *, ui_ptr)
        GET_AND_SET(std::string, ip_address)
        GET_AND_SET(int, port)
        GET_AND_SET(ID*, id)
        GET_AND_SET(char *, err_sig)
        GET_AND_SET(char *, msk_filename)
        GET_AND_SET(char *, mpk_filename)

        void run_send_message(char *dest_ip, 
							int dest_port,
							ID *dest_id);

    private :
        DECLARE_MEMBER(interface::IComm *, comm_ptr)
        DECLARE_MEMBER(interface::IPacket *, packet_ptr)
        DECLARE_MEMBER(interface::IUI *, ui_ptr)
        DECLARE_MEMBER(std::string, ip_address)
        DECLARE_MEMBER(int, port)
        DECLARE_MEMBER(ID*, id)
        DECLARE_MEMBER(char *, err_sig)
        DECLARE_MEMBER(char *, msk_filename)
        DECLARE_MEMBER(char *, mpk_filename)

        void socket_main();
        void file_main();

    };

    class Server : public User
    {

    public :

        Server(std::string ip_address, int port, ID* id);
        ~Server();
    };

    class Client : public User
    {
    
    public:

        Client(std::string ip_address, int port, ID* id);
        Client(ID* id);
        ~Client();

        void run_get_private_key(char *server_ip, 
								int server_port,
								ID *server_id=nullptr);



    };

    class UserException : public std::exception 
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

rapidjson::Document* get_cfg_doc(char* filename) ;
ID* get_id_from_doc(rapidjson::Document& doc);
void bind_objects(interface::IUser& user, 
                    interface::IComm& comm, 
                    interface::IPacket& packet, 
                    interface::IUI& uinterface,
                    char *err_sig);
void add_other_cfg(user::User& user, rapidjson::Document &doc);

#endif