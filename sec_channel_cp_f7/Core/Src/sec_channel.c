#include "sec_channel.h"
#include "rand.h"
#include "aes.h"

uint8_t* random_buf;
extern uint8_t rndb[8];
extern uint8_t ccrypt[16];
extern uint8_t master_key[16];
uint8_t s_enc[16];
uint8_t s_mac1[16];
uint8_t s_mac2[16];

extern uint8_t SCBK[16];
extern uint8_t cUID[8];
extern uint8_t icv[16];
const uint8_t osdp_scbk_default[16] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
};

static const uint8_t iv[16] = {		//This is the base icv
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

osdp_pkt_header* scs11pkt(uint8_t use_scbk_d){
	uint8_t payload[3];
	payload[0] = 0x0B;
	payload[1] = 0x11;
	payload[2] = (use_scbk_d) ? 0 : 1;

	random_buf = (uint8_t*)malloc(8);
	gen_random_bytes(random_buf);
	size_t total_data = sizeof(payload) + 8 + 1;
	uint8_t* data_pkt = (uint8_t*)malloc(total_data);
	memcpy(data_pkt, payload, 3);
	memcpy(data_pkt + 3, random_buf, 8);
	data_pkt[total_data - 1] = 0x76;		//osdp_CHLNG

	size_t total_len = sizeof(osdp_pkt_header) + total_data + 2;	//2 byte crc
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackCRC(pckt, total_data, data_pkt, 1);
	free(data_pkt);
	return pckt;
}

osdp_pkt_header* scs13pkt(uint8_t *rndb, uint8_t *s_enc, uint8_t use_scbk_d){
	//uint8_t payload[] = {0x13, 0x13};
	gen_session_keys(s_enc, s_mac1, s_mac2);
	uint8_t payload[3];
	payload[0] = 0x14;
	payload[1] = 0x13;
	payload[2] = (use_scbk_d) ? 0 : 1;
	uint8_t input[16];
	memcpy(input, rndb, 8);
	memcpy(input + 8, random_buf, 8);

	uint8_t ciphertext[16];
	memcpy(ciphertext, input, 16);

	struct AES_ctx context;
	AES_init_ctx_iv(&context, s_enc, iv);
	AES_CBC_encrypt_buffer(&context, ciphertext, 16);
	//return NULL;	//make the packet with the ciphertext and then send shit
	size_t total_data = sizeof(ciphertext) + 4;	//+1 (cmnd/reply) +2 for payload
	uint8_t* data_pkt = (uint8_t*)malloc(total_data);
	memcpy(data_pkt, payload, sizeof(payload));
	memcpy(data_pkt + sizeof(payload), ciphertext, 16);
	data_pkt[total_data - 1] = 0x77;	//osdp_SCRPYT
	size_t total_len = sizeof(osdp_pkt_header) + total_data + 2;	//2 byte crc
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackCRC(pckt, total_data, data_pkt, 1);
	free(data_pkt);
	return pckt;
}

osdp_pkt_header* scs15pkt(){
	//Only for osdp poll cmnd
	uint8_t payload[4] = {0x03, 0x15, 0x01, 0x60};		//0x60 for osdp poll
	size_t total_len = sizeof(osdp_pkt_header) + sizeof(payload) + 4 + 2;
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackMAC(pckt, 4, payload, 1, s_mac1, s_mac2);
	return pckt;
	//data will not be encrypted, only mac will be appended
}

osdp_pkt_header* scs17pkt(uint8_t* data, size_t data_len){
	//pad the data
	int N = (data_len / 16) + 1;
	uint8_t buf[N][16];
	memset(buf, 0x00, 16 * N);	//Set everything as 0x00
	memcpy(buf, data, data_len);
	//Set the 0x80 byte
	int x = data_len - 16 * (N - 1);
	buf[N - 1][x] = 0x80;		//data has been chunked

	//encrypt the data, using rmac(icv) as iv
	for(int i = 0; i < N - 1; i++){
		struct AES_ctx context;
		AES_init_ctx_iv(&context, s_enc, icv);
		AES_CBC_encrypt_buffer(&context, &buf[i][0], 16);
	}

	uint8_t payload[2] = {0x69, 0x17};
	size_t data_size = 16 * N + 2;
	uint8_t *data_pkt = (uint8_t*)malloc(data_size);
	memset(data_pkt, 0x00, data_size);
	memcpy(data_pkt, payload, 2);
	memcpy(data_pkt + 2, buf, data_size - 2);
	size_t total_len = sizeof(osdp_pkt_header) + data_size + 2 + 4;
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackMAC(pckt, data_size, data_pkt, 1, s_mac1, s_mac2);
	free(data_pkt);
	return pckt;
}

uint8_t* derive_scbk(uint8_t* cUID){
	uint8_t* cipher = (uint8_t*)malloc(16);
	memset(cipher, 0, 16);
	memcpy(cipher, cUID, 8);
	for(int i = 0; i < 8; i++){
		cipher[8 + i] = ~cUID[i];
	}

	struct AES_ctx context;
	AES_init_ctx_iv(&context, master_key, iv);
	AES_CBC_encrypt_buffer(&context, cipher, 16);
	return cipher;
}

void gen_session_keys(uint8_t* s_enc, uint8_t* s_mac1, uint8_t* s_mac2){
	//Try to get SCBK from the keystore, take cuid as an argument

	s_enc[0] = 0x01;
	s_enc[1] = 0x82;
	memcpy(&s_enc[2], random_buf, 6);
	memset(&s_enc[8], 0, 8);
	struct AES_ctx context1;
	AES_init_ctx_iv(&context1, SCBK, iv);
	AES_CBC_encrypt_buffer(&context1, s_enc, 16);


	s_mac1[0] = 0x01;
	s_mac1[1] = 0x01;
	memcpy(&s_mac1[2], random_buf, 6);
	memset(&s_mac1[8], 0, 8);
	struct AES_ctx context2;
	AES_init_ctx_iv(&context2, SCBK, iv);
	AES_CBC_encrypt_buffer(&context2, s_mac1, 16);


	s_mac2[0] = 0x01;
	s_mac2[1] = 0x02;
	memcpy(&s_mac2[2], random_buf, 6);
    memset(&s_mac2[8], 0, 8);
	struct AES_ctx context3;
	AES_init_ctx_iv(&context3, SCBK, iv);
	AES_CBC_encrypt_buffer(&context3, s_mac2, 16);
}

void gen_mac(uint8_t *data, size_t data_len, uint8_t *s_mac1, uint8_t *s_mac2, uint8_t *mac_out){

    struct AES_ctx ctx;
    uint8_t block[16];
    uint8_t cipher_out[16];

    memcpy(block, icv, 16);	//init block with rmac

    //div in chunks
    size_t blocks = (data_len + 15) / 16;

    for (size_t i = 0; i < blocks; i++) {
        uint8_t clear_block[16];
        memset(clear_block, 0, 16);
        size_t copy_len = (i == blocks - 1) ? (data_len - i * 16) : 16;
        if (copy_len > 0) {
            memcpy(clear_block, data + i * 16, copy_len);
        }

        for (int j = 0; j < 16; j++) {
            block[j] ^= clear_block[j];
        }

        if (i == blocks - 1) {
            //for last block - s_mac2
            AES_init_ctx(&ctx, s_mac2);
            memcpy(cipher_out, block, 16);
            AES_ECB_encrypt(&ctx, cipher_out);
        } else {
            //s_mac1
            AES_init_ctx(&ctx, s_mac1);
            memcpy(cipher_out, block, 16);
            AES_ECB_encrypt(&ctx, cipher_out);
        }
        memcpy(block, cipher_out, 16);
    }
    memcpy(mac_out, cipher_out, 16);
}

