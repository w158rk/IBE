#include<iostream>

#include<user.hpp>
#include<comm.hpp>
#include<ui.hpp>
#include<packet.hpp>
#include<config.h>

#include<rapidjson/document.h>
#include<rapidjson/reader.h>
#include<rapidjson/filereadstream.h>

#define ASSERT(exp) std::cerr << (exp) << std::endl

void runserver(int argc, char *argv[])
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
    user::Server server(std::string((*doc)["id"]["ip_address"].GetString()),
                        (*doc)["id"]["port"].GetInt(), 
                        server_id);
    packet::Packet packet;
    comm::Comm comm;
    ui::UInterface uinterface;

    // bind the server    
    bind_objects(server, comm, packet, uinterface, &err_sig);
    add_other_cfg(server, *doc);
    delete doc;

    server.run();
}

int main(int argc, char *argv[]) 
{

    runserver(argc, argv);

}

