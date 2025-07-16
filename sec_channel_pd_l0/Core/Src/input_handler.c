#include "input_handler.h"
#include <stdio.h>

#define RX_BUFFER 64
#define PD_ID 0x01

extern uint8_t scrypt[16];
extern uint8_t uart_rx_buf[RX_BUFFER];
extern uint8_t rnda[8];
extern volatile uint8_t response_rec;
extern uint8_t* rmac;
extern uint8_t s_enc[16];
extern uint8_t s_mac1[16];
extern uint8_t s_mac2[16];
extern UART_HandleTypeDef huart2;

void inputHandler(UART_HandleTypeDef *huart, uint16_t Size){
  uint16_t crccks = fCrcBlk(&uart_rx_buf[1], Size - 3);
  uint8_t crc_high = uart_rx_buf[Size - 2];
  uint8_t crc_low = uart_rx_buf[Size - 1];
  uint16_t crc_rec = ((uint16_t)crc_low << 8) | crc_high;

	if(crc_rec == crccks && uart_rx_buf[2] == PD_ID){
		if((uart_rx_buf[5] & 0x08) == 0x08){
			switch(uart_rx_buf[7]){
			case 0x11:
				response_rec = 1;
				scs11handler();
				break;
			case 0x13:
				response_rec = 1;
				scs13handler();
				break;
			case 0x15:
				scs15handler(Size);
				break;
			case 0x17:
				scs17handler(Size);
				break;
			}
		}
	}
}

void scs11handler(){
	memcpy(rnda, &uart_rx_buf[9], 8);
	//printHexToUart(rnda, 8);
	//print rnda
}

void scs13handler(){
	//print rndb and session keys
	memcpy(scrypt, &uart_rx_buf[9], 16);
	//print scrypt received and calculated
}

void scs15handler(uint16_t Size){
	//verify mac
	//HAL_GPIO_TogglePin(GPIOB, GPIO_PIN_7);
	int ret = verify_mac(Size);
	if(ret){
		//do stuff
		HAL_GPIO_TogglePin(GPIOB, GPIO_PIN_4);
	}
	else{
		//return error
	}
}

void scs17handler(uint16_t Size){
	int ret = verify_mac(Size);
	if(ret){
		//decrypt data
		//Last address encrypted = Size - 7
		//First address 8
		//Decrypt from uart_rx_buf[8] to Size - 7
		struct AES_ctx ctx;
		AES_init_ctx_iv(&ctx, s_enc, rmac);
		AES_CBC_decrypt_buffer(&ctx, &uart_rx_buf[8], Size - 14);		//decrypt in place
	}
	else{
		//return error
	}
}

int verify_mac(uint16_t Size) {
    uint8_t mac_rec[4];
    // Copy the received MAC from the end of the packet (Size - 6 to Size - 3)
    memcpy(mac_rec, &uart_rx_buf[Size - 6], 4);

    size_t data_len = Size - 7; // Assuming uart_rx_buf[0] is a start byte, and 4 bytes for MAC + 2 bytes for CRC (6 total) are at the end.

    struct AES_ctx ctx;
        uint8_t block[16];
        uint8_t cipher_out[16];

        // Initialize with ICV
        memcpy(block, rmac, 16);

        // Process data in 16-byte blocks
        size_t blocks = (data_len + 15) / 16;  // Round up to nearest block

        for (size_t i = 0; i < blocks; i++) {
            uint8_t clear_block[16];

            // Prepare clear block (pad with zeros if needed)
            memset(clear_block, 0, 16);
            size_t copy_len = (i == blocks - 1) ? (data_len - i * 16) : 16;
            if (copy_len > 0) {
                memcpy(clear_block, &uart_rx_buf[1] + i * 16, copy_len);
            }

            // XOR with previous result
            for (int j = 0; j < 16; j++) {
                block[j] ^= clear_block[j];
            }

            // AES encrypt with appropriate key
            if (i == blocks - 1) {
                // Last block: use SMAC-2 key
                AES_init_ctx(&ctx, s_mac2);
                memcpy(cipher_out, block, 16);
                AES_ECB_encrypt(&ctx, cipher_out);
            } else {
                // All other blocks: use SMAC-1 key
                AES_init_ctx(&ctx, s_mac1);
                memcpy(cipher_out, block, 16);
                AES_ECB_encrypt(&ctx, cipher_out);
            }

            // Copy result for next iteration
            memcpy(block, cipher_out, 16);
        }

        // Copy final MAC result
        for(int i = 0; i < 4; i++){
        	if(cipher_out[i] != mac_rec[i]){
        		return 0;
        	}
        }
        return 1;
}
