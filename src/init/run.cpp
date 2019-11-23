#include <unistd.h>
#include <set>
#include <iostream>

#include <config.h>
#include <init.hpp>
#include <comm.hpp>

using namespace init;

#define Error(err) get_user()->get_ui_ptr()->error(err)
#define Print(err) get_user()->get_ui_ptr()->print(err)

# ifdef DEBUG
# include <sstream>
# define Debug(err) get_user()->get_ui_ptr()->debug(err)
# endif

# define FOR_BLOCK_CHECK \
if(ID_equal(id, get_user()->get_id())           \
    ||sent_list.find(id)  != sent_list.end())   \
{ continue; }           \
if(sent_list.size() == cnt){ break; }   

#define TRY_BEGIN try {
#define TRY_END } catch(comm::CommException& e) { \
    std::cerr << e.what() << std::endl;     \
    continue; \
}
#undef DEBUG

void Initializer::run() 
{
    if(!config.is_set)
    {
        read_config();
    }

    if(!m_fpoly)
    {
        gen_poly();
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
                get_user()->send_init_message_1(buff, len, id);
            TRY_END
            sent_list.insert(id);

        }

        sleep(INIT_SEND_INTERVAL);

    } while(get_numbers()->size() < cnt);

    /* get all the numbers needed to calculate the share */
    cal_share();

#ifdef DEBUG
{
    std::ostringstream s;
    s << "the share is: " << BN_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif

    cal_share_with_lp();
#ifdef DEBUG
{
    std::ostringstream s;
    s << "the share with lagrange polynomial is: " << BN_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif
    
#define DEBUG
    /* round two */
    /* send F(xi)li(0)P to others and receive F(xj)lj(0)P from others*/
    Print("round two");
    sent_list.clear();
    do
    {

        len = BUFFER_SIZE;
        cal_shareP1(buff, &len);
        len2 = BUFFER_SIZE - len;
        cal_shareP2(buff+len, &len2);

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
                get_user()->send_init_message_2(buff, len, len2, id);
            TRY_END
            sent_list.insert(id);

        }

        sleep(INIT_SEND_INTERVAL);
        
    }while(get_sp_pub_points()->size() < cnt);

    cal_sP();

// CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
// CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
// CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT CURRENT 
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

    store_sP();

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
            cal_shareQ(buff, &len, id);
#ifdef DEBUG 
{
            std::ostringstream s;
            s << "the length of the EC point is : " << len << std::endl;
            s << "the EC point is: " << buff << std::endl;
            Debug(s.str());
}        
#endif

            TRY_BEGIN
            get_user()->send_init_message_3(buff, len, id);
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
    cal_sQ();

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

    store_sQ();

}