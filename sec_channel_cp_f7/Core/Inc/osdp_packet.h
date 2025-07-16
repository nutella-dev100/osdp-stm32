/*
 * osdp_packet.h
 *
 *  Created on: Jun 3, 2025
 *      Author: Admin
 */

#ifndef INC_OSDP_PACKET_H_
#define INC_OSDP_PACKET_H_

#include <stdint.h>
#include <stddef.h>
#include "stm32f7xx_hal.h"
#include "main.h"

#define OSDP_PKT_MARK	0xFF
#define OSDP_PKT_SOM	0x53
#define PKT_CNTRL_SQN	0x03
#define PKT_CNTRL_CRC	0x04
#define PKT_CNTRL_SCB	0x08

extern size_t total_len;

typedef struct __attribute__((__packed__)){
	uint8_t mark;		//for detecting packet boundary
	uint8_t som;
	uint8_t pd_address;
	uint8_t len_lsb;
	uint8_t len_msb;
	uint8_t control;
	uint8_t data[];
}osdp_pkt_header;

void populatePackChecksum(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload);
void populatePackCRC(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload, uint8_t is_scblk);
void populatePackMAC(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload, uint8_t is_scblk, uint8_t* s_mac1, uint8_t* s_mac2);
uint8_t osdp_compute_checksum(uint8_t *msg, int length);
void transmitPacket(osdp_pkt_header* buf, size_t total);

#endif /* INC_OSDP_PACKET_H_ */
