#include<user.hpp>

#include<rapidjson/filereadstream.h>
#include<iostream>

#define BUFFER_SIZE 1024
rapidjson::Document* get_cfg_doc(char* filename) 
{

    rapidjson::Document *doc = new rapidjson::Document;

    try 
    {
    
        std::FILE* fp = std::fopen(filename, "r");

        char *bp = (char *)std::malloc(BUFFER_SIZE);

        rapidjson::FileReadStream fs(fp, bp, BUFFER_SIZE);
        doc->ParseStream<rapidjson::FileReadStream>(fs);

        std::free(bp);
        std::fclose(fp);

    } 
    catch(std::exception) 
    {
    
        std::cerr << "Cannot find the file at" << filename << std::endl;
    
    }

    return doc;

} 