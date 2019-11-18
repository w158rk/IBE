#include<user.hpp>
#include<iostream>

void add_other_cfg(user::User& user, rapidjson::Document* doc)
{
    rapidjson::Value& val = (*doc)["crypto"];

    if(val.HasMember("mpk_file"))
        user.set_mpk_filename((char *)val["mpk_file"].GetString());
    if(val.HasMember("msk_file"))
        user.set_msk_filename((char *)val["msk_file"].GetString());
    if(val.HasMember("mpk_len_file"))
    {
        user.set_mpk_len_file((char *)val["mpk_len_file"].GetString());
        const char *mpk_len_filename = (char *)val["mpk_len_file"].GetString();
        FILE *fp = fopen(mpk_len_filename, "rb");
        int len;

        fread(&len, 4, 1, fp);
#ifdef DEBUG 
        fprintf(stderr, "set the length of mpk\n");
#endif
        user.set_mpk_len(len);
    }
    if(val.HasMember("msk_len_file"))
        user.set_msk_len_file((char *)val["msk_len_file"].GetString());

}