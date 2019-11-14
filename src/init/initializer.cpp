#include <utils.hpp>
#include <init.hpp>

using namespace init;

GET_AND_SET_IMPL(InitException, std::string, message)

// the definition of the initexception methods must be 
// in front of this definition
#define ERROR(x) get_user()->get_ui_ptr()->error(x)

Initializer::Initializer(interface::IUser *user)
{
    config.is_set = false;
    config.user_cnt = 0;

    set_user(user);
    user->set_initializer(this);
    read_config();

    // some members exists from the very beginning to the end of the 
    // program 
    m_numbers = new std::unordered_map<ID*, BIGNUM*>;
    m_fnumbers = true;
    m_fsp_pub_points = true;
    m_fsq_pub_points = true;

}


GET_AND_SET_IMPL(Initializer, interface::IUser *, user)
GET_AND_SET_IMPL2(Initializer, std::unordered_map<ID*, BIGNUM*>*, numbers)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT*>, sp_pub_points)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT*>, sq_pub_points)
GET_AND_SET_IMPL(Initializer, SS_POLY*, poly)


void Initializer::set_share(BIGNUM *share)
{
    if(!m_fshare)
    {
        m_share = BN_new();
    }

    BN_copy(m_share, share);
    m_fshare = true;
}
void Initializer::unset_share()
{
    if(!m_fshare)
    {
        ERROR("share is not set when calling the unset function, but the \
                program continued");
    }
    else 
    {
        BN_free(m_share);
        m_fshare = false;
    }
}
BIGNUM* Initializer::get_share()
{
    if(!m_fshare)
    {
        ERROR("share is not set when calling the get function");
        return nullptr;
    }
    return m_share;
}
struct config_t *Initializer::get_config()
{
    return &config;
}



void Initializer::read_config()
{
    char *filename = get_user()->get_cfg_filename();
    if(!filename)
    {
        throw new InitException("No filename in the user context");
    }
    rapidjson::Document *doc = get_cfg_doc(filename);

    if(!doc->HasMember("init"))
    {
        get_user()->get_ui_ptr()->error("No initial config exists");
    }
    rapidjson::Value& val = (*doc)["init"];

    if(!val.HasMember("user_ids"))
    {
        get_user()->get_ui_ptr()->error("No user ids identified in the config");
    }

    /* read the ids */
    val = val["user_ids"];
    auto id_list = val.GetArray();
    for (auto id_val=id_list.Begin(); id_val!=id_list.End(); id_val++)
    {
        ID *id = get_id_from_val(*id_val);
        config.user_ids.insert(id);
    }

    config.user_cnt = config.user_ids.size();
    config.is_set = true;

#ifdef DEBUG 
    get_user()->get_ui_ptr()->debug("read user ids finished");
#endif

}
