#ifndef UTILS_HPP 
#define UTILS_HPP 

#include<utils.h>
#include<rapidjson/document.h>

rapidjson::Document* get_cfg_doc(char* filename) ;
ID* get_id_from_doc(rapidjson::Document& doc);
ID* get_id_from_val(rapidjson::Value& val);

#endif