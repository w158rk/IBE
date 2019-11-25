#include "packet_lcl.hpp"
#include <init.hpp>

using namespace packet;
using namespace init;

Initializer *packet::init_new(Packet *packet)
{
    return new Initializer(packet->get_user_ptr());
}

std::unordered_map<ID*, BIGNUM*> *packet::init_get_numbers(Initializer *init)
{
    return init->get_numbers();
}

std::set<ID*> *packet::init_get_user_ids(init::Initializer *init)
{
    return &(init->get_config()->user_ids);
}

void packet::init_run(Initializer *init)
{
    init->run();
}


std::unordered_map<ID*, EC_POINT*> *packet::init_get_sp_pub_points(Initializer *init)
{
    return init->get_sp_pub_points();
}

std::unordered_map<ID*, EC_POINT*> *packet::init_get_sq_pub_points(Initializer *init)
{
    return init->get_sq_pub_points();
}

std::unordered_map<ID*, point_t*> *packet::init_get_sp2_pub_points(Initializer *init)
{
    return init->get_sp2_pub_points();
}
