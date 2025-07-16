#include <string.h>
#include <stdlib.h>
#include "osdp_packet.h"
#include "sec_channel.h"
#include "crc.h"

	//prevents padding between struct members
size_t total_len;
extern UART_HandleTypeDef huart1;

uint8_t osdp_compute_checksum(uint8_t *msg, int length) {
    uint8_t sum = 0;
    for (int i = 0; i < length; i++) {
        sum += msg[i];
    }
    uint8_t checksum = (uint8_t)(~(sum & 0xFF) + 1);  // 2's complement of LSB
    return checksum;
}

void populatePackChecksum(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload){
	total_len = sizeof(osdp_pkt_header) + payload_len + 1;

	pkt->mark = OSDP_PKT_MARK;
	pkt->som = OSDP_PKT_SOM;
	pkt->pd_address = 0x01;		//testing with pd

	uint16_t len_field = total_len - 1;  // length from SOM onwards
	pkt->len_lsb = (uint8_t)(len_field & 0xFF);
	pkt->len_msb = (uint8_t)((len_field >> 8) & 0xFF);

	pkt->control = 0x00;	//clear
	pkt->control |= (PKT_CNTRL_SQN & 0b00);
	pkt->control |= (PKT_CNTRL_CRC & 0b00);		//Checksum
	pkt->control |= (PKT_CNTRL_SCB & 0b00);

	memcpy(pkt->data, payload, payload_len);
	uint8_t checksum = osdp_compute_checksum(&pkt->pd_address, 4 + payload_len);
	pkt->data[payload_len] = checksum;
}

void populatePackCRC(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload, uint8_t is_scblk){
	total_len = sizeof(osdp_pkt_header) + payload_len + 2;	//2 byte crc
	pkt->mark = OSDP_PKT_MARK;
	pkt->som = OSDP_PKT_SOM;
	pkt->pd_address = 0x01;		//testing with pd

	uint16_t len_field = total_len - 1;  // length from SOM onwards
	pkt->len_lsb = (uint8_t)(len_field & 0xFF);
	pkt->len_msb = (uint8_t)((len_field >> 8) & 0xFF);

	pkt->control = 0x00;	//clear
	//pkt->control |= (PKT_CNTRL_SQN & 0b00);
	pkt->control |= PKT_CNTRL_CRC;		//CRC
	if(is_scblk)
		pkt->control |= PKT_CNTRL_SCB;

	memcpy(pkt->data, payload, payload_len);
	uint16_t crc_calc = fCrcBlk(&pkt->som, total_len - 3);
	pkt->data[payload_len + 1] = (crc_calc >> 8) & 0xFF;     // CRC high byte
	pkt->data[payload_len] = crc_calc & 0xFF;        // CRC low byte

	//pkt->data[payload_len] = crc_calc;
}

void populatePackMAC(osdp_pkt_header *pkt, size_t payload_len, uint8_t *payload, uint8_t is_scblk, uint8_t* s_mac1, uint8_t* s_mac2){
	total_len = sizeof(osdp_pkt_header) + payload_len + 2 + 4;	//+4 for the mac
	pkt->mark = OSDP_PKT_MARK;
	pkt->som = OSDP_PKT_SOM;
	pkt->pd_address = 0x01;		//testing with pd

	uint16_t len_field = total_len - 1;  // length from SOM onwards
	pkt->len_lsb = (uint8_t)(len_field & 0xFF);
	pkt->len_msb = (uint8_t)((len_field >> 8) & 0xFF);

	pkt->control = 0x00;	//clear
	pkt->control |= PKT_CNTRL_CRC;		//CRC
	if(is_scblk)
		pkt->control |= PKT_CNTRL_SCB;

	memcpy(pkt->data, payload, payload_len);
	//Now calculate mac for the entire packet
	uint8_t* temp = (uint8_t*)pkt;
	uint8_t* mac = (uint8_t*)malloc(16);
	gen_mac(temp + 1, len_field - 6, s_mac1, s_mac2, mac);

	//append 4 bytes of mac to end of pkt
	memcpy(pkt->data + payload_len, mac, 4);

	//calc and append crc
	uint16_t crc_calc = fCrcBlk(&pkt->som, total_len - 3);
	pkt->data[payload_len + 4 + 1] = (crc_calc >> 8) & 0xFF;     // CRC high byte + 4 to account for mac
	pkt->data[payload_len + 4] = crc_calc & 0xFF;        // CRC low byte
}

void transmitPacket(osdp_pkt_header* buf, size_t total){
	uint8_t* pckt = (uint8_t*)buf;
	HAL_UART_Transmit(&huart1, pckt, total, HAL_MAX_DELAY);
}
