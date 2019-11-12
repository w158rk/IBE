#include <user.hpp>

ID* get_id_from_val(rapidjson::Value& val)
{
    ID *id = new ID;
    
    id->id = (char*)val["id"].GetString();
    id->length = val["id"].GetStringLength();
    id->ip = (char *)val["ip_address"].GetString();
    id->port = val["port"].GetInt();

    ID *cur = id;
    while (! (val["parent"].IsNull()))
    {

        val = val["parent"];

        // construct the new ID
        ID *parent = new ID;
        parent->id = (char *)val["id"].GetString();
        parent->length = val["id"].GetStringLength();
        parent->ip = (char *)val["ip_address"].GetString();
        parent->port = val["port"].GetInt();
        cur->father_node = parent;

        cur = parent;

    }
    cur->father_node = nullptr;

    return id;

}