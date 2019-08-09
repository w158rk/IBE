/**
 * @file packet.h
 * @author Wang Ruikai 
 * @date August 8th, 2019
 * @brief packet preparing and handling
 */


#ifndef PACKET_H
#define PACKET_H

#include <ds.h>
#include <utils.h>
#include <config.h>


/**
 * @brief send a app packet, wrap it in a secpacket and give the 
 *          encrypt type, no signing and encrypting in this function
 * @return 1 if no error, 0 else 
 * @param[in] ctx 
 */
int send_ap(PacketCTX *ctx);

/**
 * @brief add sign to the security packet 
 * @return 1 if no error, 0 else 
 * @param[in] ctx
 */
int send_sign(PacketCTX *);
#endif