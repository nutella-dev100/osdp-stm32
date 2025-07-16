#ifndef INC_CMAC_H_
#define INC_CMAC_H_

#include "aes.h"
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

//cmac context
typedef struct {
    struct AES_ctx aes_ctx;
    uint8_t k1[AES_BLOCK_SIZE];
    uint8_t k2[AES_BLOCK_SIZE];
} aes_cmac_ctx_t;

void aes_cmac_init(aes_cmac_ctx_t* ctx, const uint8_t* key);
void aes_cmac_compute(aes_cmac_ctx_t* ctx, const uint8_t* data, size_t len, uint8_t* mac);

static void leftshift_onebit(const uint8_t* input, uint8_t* output);
static void generate_subkeys(aes_cmac_ctx_t* ctx);
static void xor_block(const uint8_t* a, const uint8_t* b, uint8_t* out);
static void pad_block(const uint8_t* data, size_t len, uint8_t* padded);

#endif /* INC_CMAC_H_ */
