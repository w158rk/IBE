#include<iostream>

#include<user.hpp>
#include<comm.hpp>
#include<init.hpp>
#include<ui.hpp>
#include<packet.hpp>
#include<config.h>

#include<rapidjson/document.h>
#include<rapidjson/reader.h>
#include<rapidjson/filereadstream.h>

#define ASSERT(exp) std::cerr << (exp) << std::endl

void runclient(int argc, char *argv[])
{
    if(argc < 2) {
        std::cerr << "Please enter the path to config file" << std::endl;
    }

    // read the config file 
    rapidjson::Document* doc = get_cfg_doc(argv[1]);

    // initialize the ID
    ID *client_id = get_id_from_doc(*doc);

    // initialize the objects at the order 
    char err_sig;
    user::User client(client_id);
    packet::Packet packet;
    comm::Comm comm;
    ui::UInterface uinterface;

    // bind the client    
    #define REINTER(type, obj) reinterpret_cast<type *>(&obj)
    bind_objects(REINTER(user::User, client), 
                    REINTER(interface::IComm, comm), 
                    REINTER(interface::IPacket, packet), 
                    REINTER(interface::IUI, uinterface), 
                    &err_sig);
    client.set_cfg_filename(argv[1]);
    client.set_user_mode(user::User::user_mode_t::USER_CLIENT);
    add_other_cfg(client, doc);

    client.run();
}

int main(int argc, char *argv[]) 
{

    try 
    {
        runclient(argc, argv);
    }
    catch(user::UserException &e)
    {
        std::cerr << e.what() << std::endl;
    }
    catch(comm::CommException &e)
    {
        std::cerr << e.what() << std::endl;
    }
    catch(packet::PacketException &e)
    {
        std::cerr << e.what() << std::endl;
    }
    catch(init::InitException &e)
    {
        std::cerr << e.what() << std::endl;
    }
}

