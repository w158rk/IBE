#include <user.hpp>

ID* get_id_from_doc(rapidjson::Document& doc)
{
    
    rapidjson::Value& val = doc["id"];


    return get_id_from_val(val);

}