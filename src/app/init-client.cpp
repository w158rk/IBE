#include<iostream>

# include<user.hpp>
# include<comm.hpp>
# include<init.hpp>
# include<ui.hpp>
# include<packet.hpp>
# include<config.h>

#include<rapidjson/document.h>
#include<rapidjson/reader.h>
#include<rapidjson/filereadstream.h>

#define ASSERT(exp) std::cerr << (exp) << std::endl

void run(int argc, char *argv[])
{
    if(argc < 2) {
        std::cerr << "Please enter the path to config file" << std::endl;
    }

    // read the config file 
    rapidjson::Document* doc = get_cfg_doc(argv[1]);

    // initialize the ID
    ID *user_id = get_id_from_doc(*doc);

    // initialize the objects at the order 
    char err_sig;
    user::User user(user_id);
    packet::Packet packet;
    comm::Comm comm;
    ui::UInterface uinterface;

    // bind the user    
    #define REINTER(type, obj) static_cast<type *>(&obj)
    bind_objects(REINTER(user::User, user), 
                    REINTER(interface::IComm, comm), 
                    REINTER(interface::IPacket, packet), 
                    REINTER(interface::IUI, uinterface), 
                    &err_sig);
    user.set_cfg_filename(argv[1]);
    user.set_user_mode(user::User::user_mode_t::USER_INIT_CLIENT);
    add_other_cfg(user, doc);

    user.run_init_client();
}

int main(int argc, char *argv[]) 
{
    try 
    {
        run(argc, argv);
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

