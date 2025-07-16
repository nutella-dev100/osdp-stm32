/*
 * sec_channel.h
 *
 *  Created on: Jun 25, 2025
 *      Author: Admin
 */

#ifndef INC_SEC_CHANNEL_H_
#define INC_SEC_CHANNEL_H_

#include "osdp_packet.h"

extern uint8_t* random_buf;

osdp_pkt_header* scs12pkt(uint8_t use_scbk_d);
osdp_pkt_header* scs14pkt(uint8_t use_scbk_d);
osdp_pkt_header* scs16pkt();
osdp_pkt_header* scs18pkt(uint8_t* data, size_t data_len);
void gen_session_keys(uint8_t* s_enc, uint8_t* s_mac1, uint8_t* s_mac2);
uint8_t verify_scrypt(uint8_t *rec, uint8_t* rnda, uint8_t* rndb, uint8_t* s_enc);
void gen_mac(uint8_t *data, size_t data_len, uint8_t *s_mac1, uint8_t *s_mac2, uint8_t *mac_out);
#endif /* INC_SEC_CHANNEL_H_ */
