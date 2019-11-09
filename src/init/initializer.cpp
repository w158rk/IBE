#include <utils.hpp>
#include <init.hpp>

using namespace init;


GET_AND_SET_IMPL(Initializer, interface::IUser *, user)
GET_AND_SET_IMPL(Initializer, std::set<BIGNUM>, numbers)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT>, sp_pub_points)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT>, sq_pub_points)
GET_AND_SET_IMPL(Initializer, SS_POLY, poly)
GET_AND_SET_IMPL(Initializer, BIGNUM*, share)

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

    /* CURRENT */
    /* access the elements in an array */

}