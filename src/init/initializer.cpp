#include <utils.hpp>
#include <init.hpp>

using namespace init;

#define ERROR(x) get_user()->get_ui_ptr()->error(x)

GET_AND_SET_IMPL(Initializer, interface::IUser *, user)
GET_AND_SET_IMPL(Initializer, std::set<BIGNUM*>, numbers)
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


Initializer::Initializer(interface::IUser *user)
{
    config.is_set = false;
    config.user_cnt = 0;

    set_user(user);
    read_config();

}

void Initializer::read_config()
{
    rapidjson::Document *doc = get_cfg_doc(get_user()->get_cfg_filename());

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
    auto id_list = val.GetArray();
    for (auto id_val=id_list.Begin(); id_val!=id_list.End(); id_val++)
    {
        ID *id = get_id_from_val(*id_val);
        config.user_ids.insert(id);
    }

    config.user_cnt = config.user_ids.size();
    config.is_set = true;

}