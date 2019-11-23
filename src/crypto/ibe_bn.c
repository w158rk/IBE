/**
 * 
 * @file    ibe_bn
 * @brief   all the functions related to bn in ibe 
 * 
 */

#include "smx_lcl.h"
#include "ibe_err.h"
#include "ibe_lcl.h"

const BIGNUM *IBE_get0_order(void)
{
	return SMX_get0_order();
}
