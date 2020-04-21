#include <unistd.h>
#include <set>
#include <iostream>
#include <ui.hpp>
#include <time.h>

#include <config.h>
#include "init_lcl.hpp"

using namespace init;

#define Error(err) throw InitException(err)
#define Print(err) ui::UInterface::print(err)

# ifdef DEBUG
# include <sstream>
# define Debug(err) ui::UInterface::debug(err)
# endif

# define FOR_BLOCK_CHECK \
if(ID_equal(id, user_get_id(get_user()))           \
    ||sent_list.find(id)  != sent_list.end())   \
{ continue; }           \
if(sent_list.size() == cnt){ break; }   

#define TRY_BEGIN try {
#define TRY_END } catch(InitException& e) { \
    std::cerr << e.what() << std::endl;     \
    continue; \
}

void Initializer::run() 
{
    if(!config.is_set)
    {
        read_config();
    }

    if(!m_fpoly)
    {
        double start,end,cost;
        start=clock();
        gen_poly();
        end=clock();
        cost=(end-start)/CLOCKS_PER_SEC*1000;
        printf("poly time is: %f ms\n",cost);
    }
    
#ifdef DEBUG
{
    char dbg_buff[BUFFER_SIZE] = {'\0'};
    int len = BUFFER_SIZE;
    SS_poly2str(dbg_buff, &len, m_poly);
    std::ostringstream s;
    s << "the polynomial generated" << std::endl;
    s << dbg_buff;
    Debug(s.str());
}


#endif
    user::User *userptr = get_user();

{
    FILE *fp = NULL;

#ifdef DEBUG 
    Debug("the local system has not been setup, generate a new system");
#endif

    if((fp=fopen(user_get_mpk_filename(userptr), "rb")) == NULL)
    {
        user_sys_setup(userptr);
    }
    else {
        fclose(fp);
    }

}
    Print("begin to initialize the system");

    /* round one */
    /* send fi(xj) to others and receive fj(xi) from others */
    char buff[BUFFER_SIZE] = {'\0'};
    int len = BUFFER_SIZE;
    int len2 = 0;           // in round 2, there are two string supposed to be sent, so the two length are necessary both
    int cnt = config.user_cnt-1;

    Print("round one");

    std::set<ID *> sent_list;

    
    do {
        #ifdef DEBUG
        {        
                std::ostringstream s;
                s << "the size of the numbers: " <<  get_numbers()->size() << std::endl;
                Debug(s.str());
        }
        #endif
        /* as the handle of the received packet will be in packet module 
            what we do here is just send the N packet to other users */
        
        for (ID* id : config.user_ids)
        {

            FOR_BLOCK_CHECK
            
            /* there are must some connection error happens here, but we can not 
                let the program stop by this kind of exception */
            /* one of the solution here is to check if the port is open first, if 
                it is not, just skip this round and wait for the next send behavior */
            len = BUFFER_SIZE;
            cal_fx(buff, &len, id);
        #ifdef DEBUG
        {
            std::ostringstream s;
            s << "f(x) for " << id->id << ": " << buff << std::endl;
            Debug(s.str());
        }
        #endif

            TRY_BEGIN
                user_send_init_message_1(get_user(), buff, len, id);
            TRY_END
            sent_list.insert(id);

        }

        sleep(INIT_SEND_INTERVAL);

    } while(get_numbers()->size() < cnt);

    /* get all the numbers needed to calculate the share */
    long start, end;

    start = clock();
    cal_share();

#ifdef DEBUG
{
    std::ostringstream s;
    s << "the share is: " << BN_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif

    cal_share_with_lp();
    end = clock();
    printf("time of calculate the share: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);

#ifdef DEBUG
{
    std::ostringstream s;
    s << "the share with lagrange polynomial is: " << BN_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif
    /* round two */
    /* send F(xi)li(0)P to others and receive F(xj)lj(0)P from others*/
    Print("round two");
    sent_list.clear();

    do
    {

        len = BUFFER_SIZE;

        start = clock();
        cal_shareP1(buff, &len);
        len2 = BUFFER_SIZE - len;
        cal_shareP2(buff+len, &len2);
        end = clock();
        printf("time of calculate the shareP: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);
#ifdef DEBUG 
{
        std::ostringstream s;
        s << "len1: " << len << std::endl;
        s << "len2: " << len2 << std::endl;
        Debug(s.str());
}
#endif

        for (ID *id : config.user_ids)
        {
            FOR_BLOCK_CHECK

            TRY_BEGIN
                user_send_init_message_2(get_user(), buff, len, len2, id);
            TRY_END
            sent_list.insert(id);

        }

        sleep(INIT_SEND_INTERVAL);
        
    }while(get_sp_pub_points()->size() < cnt);


    start = clock();
    cal_sP();
    end = clock();
    printf("time of calculate the sP: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);

#ifdef DEBUG
{
    BN_CTX *ctx = BN_CTX_new();
    std::ostringstream s;
    s << " the sP1 is: ";
    s << ibe_ec2str(get_sP(), ctx) << std::endl;
    Debug(s.str());
    BN_CTX_free(ctx);
}
{
    std::ostringstream s;
    char buf[150];
    s << "the sP2 is: ";
    ibe_point_to_octets(get_Ppub2(), buf);
    s << buf << std::endl;
    Debug(s.str());
}
#endif

    start = clock();
    store_sP();
    end = clock();
    printf("time of store the sP: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);

    /* round three */
    /* send F(xi)li(0)Q to others and receive F(xj)lj(0)Q from others*/
    Print("round three");
    sent_list.clear();

    do
    {
        
        for (ID *id : config.user_ids)
        {
            FOR_BLOCK_CHECK

            len = BUFFER_SIZE;
            start = clock();
            cal_shareQ(buff, &len, id);
            end = clock();
            printf("time of calculate the shareQ: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);
#ifdef DEBUG 
{
            std::ostringstream s;
            s << "the length of the EC point is : " << len << std::endl;
            s << "the EC point is: " << buff << std::endl;
            Debug(s.str());
}        
#endif

            TRY_BEGIN
            user_send_init_message_3(get_user(), buff, len, id);
            TRY_END

            sent_list.insert(id);
        }

        sleep(INIT_SEND_INTERVAL);

    }while(get_sq_pub_points()->size() < config.user_cnt-1);

    // [IMPORTANT]
    /**
     * the sP and sQ share the same member variable 
     * so in cal_SQ, instead of using set_SQ, 
     * we use EC_POINT_copy when necessary 
     */
    start = clock();
    cal_sQ();
    end = clock();
    printf("time of calculate the sQ: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);
#
#ifdef DEBUG
{
    BN_CTX *ctx = BN_CTX_new();
    std::ostringstream s;
    s << " the sQ is: ";
    s << ibe_ec2str(get_sP(), ctx) << std::endl;
    Debug(s.str());
    BN_CTX_free(ctx);
}
#endif

    start = clock();
    store_sQ();
    end = clock();
    printf("time of store the sQ: %f msec\n", (double)(end-start)/CLOCKS_PER_SEC*1000);

}