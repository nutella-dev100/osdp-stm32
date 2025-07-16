/*
 * sec_channel.h
 *
 *  Created on: Jun 24, 2025
 *      Author: Admin
 */

#ifndef INC_SEC_CHANNEL_H_
#define INC_SEC_CHANNEL_H_

#include "osdp_packet.h"
#include "pd_keystore.h"

extern uint8_t* random_buf;

osdp_pkt_header* scs11pkt(uint8_t use_scbk_d);
osdp_pkt_header* scs13pkt(uint8_t *rndb, uint8_t *s_enc, uint8_t use_scbk_d);
osdp_pkt_header* scs15pkt();
osdp_pkt_header* scs17pkt(uint8_t* data, size_t data_len);
uint8_t* derive_scbk(uint8_t* cUID);
void gen_session_keys(uint8_t* s_enc, uint8_t* s_mac1, uint8_t* s_mac2);
void gen_mac(uint8_t *data, size_t data_len, uint8_t *s_mac1, uint8_t *s_mac2, uint8_t *mac_out);

#endif /* INC_SEC_CHANNEL_H_ */
