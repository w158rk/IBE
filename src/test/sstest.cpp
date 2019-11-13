#include<iostream>

#include<user.hpp>
#include<comm.hpp>
#include<ui.hpp>
#include<packet.hpp>
#include<init.hpp>

#include<config.h>

#include<rapidjson/document.h>
#include<rapidjson/reader.h>
#include<rapidjson/filereadstream.h>

bool test_id2num(user::User *u)
{
    BIGNUM *res = BN_new();
    for (int i=0; i<10; i++){
        SS_id2num_init(res, u->get_id(), 
                u->get_mpk_filename());
        std::cout << BN_bn2hex(res) << std::endl;
    }
    return true;
}

void runtest(int argc, char *argv[])
{
    if(argc < 2) {
        std::cerr << "Please enter the path to config file" << std::endl;
    }

    // read the config file 
    rapidjson::Document* doc = get_cfg_doc(argv[1]);

    // initialize the ID
    ID *server_id = get_id_from_doc(*doc);

    // initialize the objects at the order 
    char err_sig;
    user::User server(server_id);
    packet::Packet packet;
    comm::Comm comm;
    ui::UInterface uinterface;

    // bind the server    
    #define REINTER(type, obj) reinterpret_cast<type *>(&obj)
    bind_objects(REINTER(interface::IUser, server), 
                    REINTER(interface::IComm, comm), 
                    REINTER(interface::IPacket, packet), 
                    REINTER(interface::IUI, uinterface), 
                    &err_sig);

    // configurations other from the ID
    server.set_cfg_filename(argv[1]);
    add_other_cfg(server, doc);

    test_id2num(&server);

    init::Initializer initializer(&server);
    initializer.run();

}

int main(int argc, char *argv[]) 
{
    try 
    {
        runtest(argc, argv);
    }
    catch(init::InitException &e)
    {
        std::cerr << e.what() << std::endl;
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

}

