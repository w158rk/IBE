#include <config.h>
#include <init.hpp>
#include <set>

using namespace init;

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
    
    get_user()->get_ui_ptr()->print("begin to initialize the system");

    /* round one */
    /* send fi(xj) to others and receive fj(xi) from others */
    char buff[BUFFER_SIZE];
    int len = BUFFER_SIZE;
    int cnt = config.user_cnt-1;

    get_user()->get_ui_ptr()->print("round one");

    std::set<ID *> sent_list;

    // while(get_numbers().size() < cnt)
    {

        /* as the handle of the received packet will be in packet module 
            what we do here is just send the N packet to other users */

        for (ID* id : config.user_ids)
        {

            // override the opcode
            if(ID_equal(id, get_user()->get_id()))
            {
                continue;
            }

            if(sent_list.size() == cnt)
            {
                break;
            }
            
            if(sent_list.find(id)  != sent_list.end())
            {
                continue;
            }
            /* there are must some connection error happens here, but we can not 
                let the program stop by this kind of exception */
            /* one of the solution here is to check if the port is open first, if 
                it is not, just skip this round and wait for the next send behavior */
            cal_fx(buff, &len, id);
            try
            {
                get_user()->send_init_message_1(buff, len, id);
            }
            catch(const std::exception& e)
            {
                continue;
            }

            sent_list.insert(id);

        }

    }

    /* get all the numbers needed to calculate the share */
    cal_share();


    /* round two */
    /* send F(xi)li(0)P to others and receive F(xj)lj(0)P from others*/

    get_user()->get_ui_ptr()->print("round two");
    while(get_sp_pub_points().size() < cnt)
    {

        len = BUFFER_SIZE;
        cal_shareP(buff, &len);
        for (ID *id : config.user_ids)
        {

            get_user()->send_init_message_2(buff, len, id);

        }
        
    }

    /* round three */
    /* send F(xi)li(0)Q to others and receive F(xj)lj(0)Q from others*/
    get_user()->get_ui_ptr()->print("round three");
    while(get_sq_pub_points().size() < config.user_cnt-1)
    {
        
        len = BUFFER_SIZE;
        for (ID *id : config.user_ids)
        {

            cal_shareQ(buff, &len, id);
            get_user()->send_init_message_3(buff, len, id);
        }

    }


}