
/**
 * file: server.cpp
 * function of servers 
 * 
 *      - setup a system by generating the mpk, msk file
*/

extern "C" {
    #include <sys.h>
    #include <openssl/sm9.h>
    #include <openssl/bio.h>
}

#include<user.hpp>
#include<packet.hpp>
#ifdef DEBUG 
#include<sstream>
#include<ui.hpp>
#define Debug(info) ui::UInterface::debug(info)
#endif
# include <init.hpp>


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
    char *filename = NULL;
    ibe_gen_sk_filename(&filename, get_id());
    if(!put_sk_fp(filename, &sk, sk_len))
    {
        interface::IUI::debug("output sk failed");
        throw new std::exception;
    }
    ibe_free_filename(filename);

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

void User::sys_read()
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

    /* if the node is top node, it needs to generate its certificate */
    if(User::get_id()->father_node==nullptr)        
    {

        SignMesg server_sig, server_sig2;

        /* generate inner sign */

        /* get global-sP */
        IBEPublicParameters ss_mpk = NULL;
        get_mpk_fp(GLOBAL_MPK_FILENAME, &ss_mpk);

        server_sig.PP = ss_mpk;
        server_sig.ID = User::get_id()->id;
        int id_len = strlen(User::get_id()->id);
        *(int *)(server_sig.id_len) = id_len;
        server_sig.sign_data = NULL;
        *(int *)(server_sig.sign_len) = 0;
        server_sig.front = nullptr;

        /* generate final sign */
        
        /* get domain sP */
        IBEPublicParameters mpk = NULL;
        GENERATE_MPK_FILENAME(get_id()->id,strlen(get_id()->id))
        get_mpk_fp(mpk_filename, &mpk);
        FREE_MPK_FILENAME;

        server_sig2.PP = mpk;
        server_sig2.ID = User::get_id()->id;
        *(int *)(server_sig2.id_len) = id_len;
        char *sign = (char *)std::malloc(BUFFER_LEN);
        size_t s_len = BUFFER_LEN;

        /* genreate sign */
        char *data = (char *)malloc(id_len+IBE_MPK_LEN);
        memcpy(data,get_id()->id, id_len);
        memcpy(data+id_len,mpk,IBE_MPK_LEN);
        IBEPrivateKey global_sk = NULL;
        GENERATE_GLOBAL_SK_FILENAME(get_id())
        get_sk_fp(filename, &global_sk);
        FREE_GLOBAL_SK_FILENAME;   
        if(!(ibe_sign(data, id_len+IBE_MPK_LEN, sign, &s_len, &global_sk, 380)))
        {
            fprintf(stderr, "sign error\n");
        }

        server_sig2.sign_data = sign;
        *(int *)server_sig2.sign_len = s_len;
        server_sig2.front = &server_sig;

        char *sig = (char *)malloc(BUFFER_LEN);
        int server_sig_len = sign_to_bytes(&server_sig2, sig);

        GENERATE_SIGN_FILENAME(User::get_id()->id, strlen(User::get_id()->id)) 
        FILE *fp1;
        if((fp1=fopen(filename_sign,"wb+"))==NULL)
        {
            interface::IUI::error("file cannot open \n");  
        }
        std::fwrite(sig, 1,  server_sig_len, fp1);
        fclose(fp1);
        FREE_SIGN_FILENAME;

        GENERATE_SIGN_LEN_FILENAME(User::get_id()->id, strlen(User::get_id()->id)) 

        FILE *fp2;
        if((fp2=fopen(filename_len_sign,"wb+"))==NULL)
        {
            interface::IUI::error("file cannot open \n");  
        }
        std::fwrite(&server_sig_len, sizeof(server_sig_len), 1, fp2);
        fclose(fp2);

        FREE_SIGN_LEN_FILENAME;
    }


}



void User::sys_init()
{
    if(!m_finitializer)
    {
        init::Initializer* initializer = new init::Initializer(this);
    }

    get_initializer()->run();
    unset_initializer();
}
