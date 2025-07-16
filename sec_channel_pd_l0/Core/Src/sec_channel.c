#include "sec_channel.h"
#include "rand.h"
#include "aes.h"

uint8_t* random_buf;
extern uint8_t rnda[8];
extern uint8_t scrypt[16];
extern const uint8_t cUID[8];
extern const uint8_t SCBK[16];
uint8_t s_enc[16];
uint8_t s_mac1[16];
uint8_t s_mac2[16];
uint8_t* rmac;

static const uint8_t iv[16] = {		//this is the base icv
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

void gen_session_keys(uint8_t* s_enc, uint8_t* s_mac1, uint8_t* s_mac2){
	s_enc[0] = 0x01;
	s_enc[1] = 0x82;
	memcpy(&s_enc[2], rnda, 6);
	memset(&s_enc[8], 0, 8);
	struct AES_ctx context1;
	AES_init_ctx_iv(&context1, SCBK, iv);
	AES_CBC_encrypt_buffer(&context1, s_enc, 16);


	s_mac1[0] = 0x01;
	s_mac1[1] = 0x01;
	memcpy(&s_mac1[2], rnda, 6);
	memset(&s_mac1[8], 0, 8);
	struct AES_ctx context2;
	AES_init_ctx_iv(&context2, SCBK, iv);
	AES_CBC_encrypt_buffer(&context2, s_mac1, 16);


	s_mac2[0] = 0x01;
	s_mac2[1] = 0x02;
	memcpy(&s_mac2[2], rnda, 6);
    memset(&s_mac2[8], 0, 8);
	struct AES_ctx context3;
	AES_init_ctx_iv(&context3, SCBK, iv);
	AES_CBC_encrypt_buffer(&context3, s_mac2, 16);
}

osdp_pkt_header* scs12pkt(uint8_t use_scbk_d){
	//use rnda rndb and some shit
	//uint8_t payload[] = {0x23, 0x12};
	uint8_t payload[3];
	payload[0] = 0x24;
	payload[1] = 0x12;
	payload[2] = (use_scbk_d) ? 0 : 1;
	size_t random_buf_size = 8;
	random_buf = (uint8_t*)malloc(random_buf_size);
	gen_random_bytes(random_buf);	//PD generates its own rndb[8]

	//generate session keys s_enc, s_mac1, s_mac2
	gen_session_keys(s_enc, s_mac1, s_mac2);

	//generate ccrypt
	uint8_t ccrypt_buf[16];
	memset(ccrypt_buf, 0, 16);
	memcpy(ccrypt_buf, random_buf, 8);
	memcpy(ccrypt_buf + 8, rnda, 8);		//ccrypt is now rndb[8] || rnda[8]

	struct AES_ctx context;
	AES_init_ctx_iv(&context, s_enc, iv);
	AES_CBC_encrypt_buffer(&context, ccrypt_buf, 16);		//ciphertext is now encrypted

	//cuid-8, rndb-8, ccrypt-16, osdp-5, cmnd-1, crc-2
	size_t total_data = sizeof(cUID) + sizeof(ccrypt_buf) + sizeof(random_buf) + 1 + 3;	//+1 for cmnd/reply + 3 for payload
	uint8_t* data_pkt = (uint8_t*)malloc(total_data);
	size_t offset = 0;
	memset(data_pkt, 0, total_data);
	memcpy(data_pkt, payload, 3); offset += 3;
	memcpy(data_pkt + offset, cUID, 8); offset += 8;
	memcpy(data_pkt + offset, random_buf, 8); offset += 8;
	memcpy(data_pkt + offset, ccrypt_buf, 16);
	data_pkt[total_data - 1] = 0x76;

	size_t total_len = sizeof(osdp_pkt_header) + total_data + 2;	//2 byte crc
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackCRC(pckt, total_data, data_pkt, 1);
	free(data_pkt);
	return pckt;
}

osdp_pkt_header* scs14pkt(uint8_t use_scbk_d){
	//receive scrypt from cp
	uint8_t ret = verify_scrypt(scrypt, rnda, random_buf, s_enc);
	if(ret){
		//do stuff
		HAL_GPIO_TogglePin(GPIOA, GPIO_PIN_5);
        uint8_t payload[3] = {0x14, 0x14, 0x01};	//Next 16 bytes are the mac
        size_t total_data = 20;
        //generate rmac
        struct AES_ctx context;
        rmac = (uint8_t*)malloc(16);
        memcpy(rmac, scrypt, 16);
        AES_init_ctx_iv(&context, s_mac1, NULL);
        AES_CBC_encrypt_buffer(&context, rmac, 16);	//encrypted using smac1 in ECB
        AES_init_ctx_iv(&context, s_mac2, NULL);
        AES_CBC_encrypt_buffer(&context, rmac, 16);	//computed rmac
        uint8_t* data_pkt = (uint8_t*)malloc(total_data);
        memset(data_pkt, 0, total_data);
        size_t offset = 0;
        memcpy(data_pkt, payload, 3); offset += 3;
        memcpy(data_pkt + offset, rmac, 16);
        data_pkt[total_data - 1] = 0x78;
        size_t total_len = sizeof(osdp_pkt_header) + total_data + 2;
        osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
        populatePackCRC(pckt, total_data, data_pkt, 1);
        free(data_pkt);
        return pckt;
	}
	else{
		//do stuff
        uint8_t payload[3] = {0x03, 0x14, 0x00};
        size_t total_data = 4;
        uint8_t* data_pkt = (uint8_t*)malloc(total_data);
        memset(data_pkt, 0, total_data);
        memcpy(data_pkt, payload, 3);
		data_pkt[total_data - 1] = 0x78;
        size_t total_len = sizeof(osdp_pkt_header) + total_data + 2;
        osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
        populatePackCRC(pckt, total_data, data_pkt, 1);
        free(data_pkt);
        return pckt;
	}
}

osdp_pkt_header* scs16pkt(){
	//Only for osdp poll cmnd
	uint8_t payload[4] = {0x03, 0x16, 0x01, 0x40};		//0x60 for osdp poll
	size_t total_len = sizeof(osdp_pkt_header) + sizeof(payload) + 4 + 2;
	osdp_pkt_header *pckt = (osdp_pkt_header*)malloc(total_len);
	populatePackMAC(pckt, 4, payload, 1, s_mac1, s_mac2);
	return pckt;
	//data will not be encrypted, only mac will be appended
}

osdp_pkt_header* scs18pkt(uint8_t* data, size_t data_len){
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
		AES_init_ctx_iv(&context, s_enc, rmac);
		AES_CBC_encrypt_buffer(&context, &buf[i][0], 16);
	}

	uint8_t payload[2] = {0x69, 0x18};
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

uint8_t verify_scrypt(uint8_t *rec, uint8_t* rnda, uint8_t* rndb, uint8_t* s_enc){
	uint8_t* ciphertext = (uint8_t*)malloc(16);
	memset(ciphertext, 0, 16);
	memcpy(ciphertext, rndb, 8);
	memcpy(ciphertext + 8, rnda, 8);

	struct AES_ctx context;
	AES_init_ctx_iv(&context, s_enc, iv);
	AES_CBC_encrypt_buffer(&context, ciphertext, 16);

	for(int i = 0; i < 16; i++){
		if(ciphertext[i] != rec[i])
			return 0;
	}
	return 1;
}

void gen_mac(uint8_t *data, size_t data_len, uint8_t *s_mac1, uint8_t *s_mac2, uint8_t *mac_out){

    struct AES_ctx ctx;
    uint8_t block[16];
    uint8_t cipher_out[16];

    memcpy(block, rmac, 16);	//init block with rmac

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

