#include<user.hpp>

void add_other_cfg(user::User& user, rapidjson::Document& doc)
{
    rapidjson::Value& val = doc["crypto"];

    if(val.HasMember("mpk_file"))
        user.set_mpk_filename((char *)val["mpk_file"].GetString());
    if(val.HasMember("msk_file"))
        user.set_msk_filename((char *)val["msk_file"].GetString());

}