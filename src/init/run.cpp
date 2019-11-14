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
    
    Print("begin to initialize the system");

    /* round one */
    /* send fi(xj) to others and receive fj(xi) from others */
    char buff[BUFFER_SIZE];
    int len = BUFFER_SIZE;
    int cnt = config.user_cnt-1;

    Print("round one");

    std::set<ID *> sent_list;

    
    do {
#ifdef DEBUG
        std::ostringstream s;
        s << "the size of the numbers: " <<  get_numbers()->size() << std::endl;
        Debug(s.str());
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
    s << "the share is: " << SS_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif

    cal_share_with_lp();
#ifdef DEBUG
{
    std::ostringstream s;
    s << "the share with lagrange polynomial is: " << SS_bn2str(get_share()) << std::endl;
    Debug(s.str());
}
#endif
    

    /* round two */
    /* send F(xi)li(0)P to others and receive F(xj)lj(0)P from others*/
    Print("round two");
    sent_list.clear();
    // while(get_sp_pub_points().size() < cnt)
    {

        len = BUFFER_SIZE;
        cal_shareP(buff, &len);

#ifdef DEBUG 
{
        std::ostringstream s;
        s << "the length of the share P is : " << len << std::endl;
        s << "the share P is: " << buff << std::endl;
        Debug(s.str());
}        
#endif

        for (ID *id : config.user_ids)
        {
            FOR_BLOCK_CHECK

            TRY_BEGIN
                get_user()->send_init_message_2(buff, len, id);
            TRY_END
            sent_list.insert(id);

        }
        
    }

    /* round three */
    /* send F(xi)li(0)Q to others and receive F(xj)lj(0)Q from others*/
    Print("round three");
    sent_list.clear();

    while(get_sq_pub_points().size() < config.user_cnt-1)
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

    }


}