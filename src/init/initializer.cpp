#include <init.hpp>

using namespace init;


GET_AND_SET_IMPL(Initializer, interface::IUser *, user)
GET_AND_SET_IMPL(Initializer, std::set<BIGNUM>, numbers)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT>, sp_pub_points)
GET_AND_SET_IMPL(Initializer, std::set<EC_POINT>, sq_pub_points)
