
/**
 * file: server.cpp
 * function of servers 
 * 
 *      - setup a system by generating the mpk, msk file
*/

#include<user.hpp>
#ifdef DEBUG 
#include<sstream>
#endif

extern "C" {
    #include <sys.h>
    #include <openssl/sm9.h>
    #include <openssl/bio.h>
}


using namespace user;

void User::sys_setup()
{

    ibe_setup(
        get_mpk_filename(),
        get_msk_filename(),
        get_mpk_len_file(),
        get_msk_len_file()
    );

    /* read the length from the mpk-len and msk-len file */
    long mpk_len, msk_len;
    FILE *fp = std::fopen(get_mpk_len_file(), "rb");
    std::fread(&mpk_len, sizeof(mpk_len), 1, fp);

#ifdef DEBUG 
{
    std::ostringstream s;
    s << "the length of mpk read: " << mpk_len;
    interface::IUI::debug(s.str());
}    
#endif

    set_mpk_len(mpk_len);
    std::fclose(fp);

    fp = std::fopen(get_msk_len_file(), "rb");
    std::fread(&msk_len, sizeof(msk_len), 1, fp);

#ifdef DEBUG 
{
    std::ostringstream s;
    s << "the length of msk read: " << msk_len;
    interface::IUI::debug(s.str());
}    
#endif

    set_msk_len(msk_len);
    std::fclose(fp);

    /* generate the private key for the user itself */
    IBEMasterSecret msk = NULL;
    if(!get_msk_fp(get_msk_filename(), &msk))
    {
        interface::IUI::debug("get msk from file failed");
        throw new std::exception;
    }

    IBEPrivateKey sk = NULL;
    long sk_len = 0;
    if(!ibe_extract(&sk, &sk_len, &msk, msk_len, get_id()->id, get_id()->length))
    {
        interface::IUI::debug("generate sk failed");
        throw new std::exception;
    }

        /* output the sk file */
        GENERATE_SK_FILENAME((get_id()))
        if(!put_sk_fp(filename, &sk, sk_len))
        {
            interface::IUI::debug("output sk failed");
            throw new std::exception;
        }

    set_sk_len(sk_len);

    /* output the sk length and set the environment */
    {
        GENERATE_SK_LEN_FILENAME(get_id()) 
        fp = std::fopen(filename, "wb");
        std::fwrite(&sk_len, sizeof(sk_len), 1, fp);
        std::fclose(fp);
        FREE_SK_LEN_FILENAME
    }


}

void User::sys_init()
{

    /* read the length from the mpk-len and msk-len file */
    long mpk_len, msk_len;
    FILE *fp = std::fopen(get_mpk_len_file(), "rb");
    std::fread(&mpk_len, sizeof(mpk_len), 1, fp);

#ifdef DEBUG 
{
    std::ostringstream s;
    s << "the length of mpk read: " << mpk_len;
    interface::IUI::debug(s.str());
}    
#endif

    set_mpk_len(mpk_len);
    std::fclose(fp);

    fp = std::fopen(get_msk_len_file(), "rb");
    std::fread(&msk_len, sizeof(msk_len), 1, fp);

#ifdef DEBUG 
{
    std::ostringstream s;
    s << "the length of msk read: " << msk_len;
    interface::IUI::debug(s.str());
}    
#endif

    set_msk_len(msk_len);
    std::fclose(fp);

    long sk_len;
    /* read the sk length and set the environment */
    {
        GENERATE_SK_LEN_FILENAME(get_id()) 
        fp = std::fopen(filename, "rb");
        std::fread(&sk_len, sizeof(sk_len), 1, fp);
        std::fclose(fp);
        FREE_SK_LEN_FILENAME
    }
    set_sk_len(sk_len);
#ifdef DEBUG 
{
    std::ostringstream s;
    s << "the length of sk: " << sk_len;
    interface::IUI::debug(s.str());
}    
#endif


}