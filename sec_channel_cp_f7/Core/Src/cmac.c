#include "cmac.h"

void aes_cmac_init(aes_cmac_ctx_t* ctx, const uint8_t* key) {
    AES_init_ctx(&ctx->aes_ctx, key);
    generate_subkeys(ctx);
}

void aes_cmac_compute(aes_cmac_ctx_t* ctx, const uint8_t* data, size_t len, uint8_t* mac) {
    uint8_t x[AES_BLOCK_SIZE] = {0};
    uint8_t y[AES_BLOCK_SIZE];
    const uint8_t* pos = data;
    size_t remaining = len;

    while (remaining > AES_BLOCK_SIZE) {
        xor_block(x, pos, y);
        memcpy(x, y, AES_BLOCK_SIZE);
        AES_ECB_encrypt(&ctx->aes_ctx, x);
        pos += AES_BLOCK_SIZE;
        remaining -= AES_BLOCK_SIZE;
    }

    // Process final block
    if (remaining == AES_BLOCK_SIZE) {
        // Complete final block - use K1
        xor_block(x, pos, y);
        xor_block(y, ctx->k1, x);
    } else {
        // Incomplete final block - pad and use K2
        uint8_t padded[AES_BLOCK_SIZE];
        pad_block(pos, remaining, padded);
        xor_block(x, padded, y);
        xor_block(y, ctx->k2, x);
    }

    // Final encryption
    AES_ECB_encrypt(&ctx->aes_ctx, x);
    memcpy(mac, x, AES_BLOCK_SIZE);
}

static void generate_subkeys(aes_cmac_ctx_t* ctx) {
    uint8_t L[AES_BLOCK_SIZE] = {0};
    const uint8_t Rb[AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};

    // Generate L = AES_K(0^128)
    AES_ECB_encrypt(&ctx->aes_ctx, L);

    // Generate K1
    if (L[0] & 0x80) {
        leftshift_onebit(L, ctx->k1);
        xor_block(ctx->k1, Rb, ctx->k1);
    } else {
        leftshift_onebit(L, ctx->k1);
    }

    // Generate K2
    if (ctx->k1[0] & 0x80) {
        leftshift_onebit(ctx->k1, ctx->k2);
        xor_block(ctx->k2, Rb, ctx->k2);
    } else {
        leftshift_onebit(ctx->k1, ctx->k2);
    }
}

static void leftshift_onebit(const uint8_t* input, uint8_t* output) {
    uint8_t carry = 0;
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
        output[i] = (input[i] << 1) | carry;
        carry = (input[i] & 0x80) ? 1 : 0;
    }
}

static void xor_block(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void pad_block(const uint8_t* data, size_t len, uint8_t* padded) {
    memset(padded, 0, AES_BLOCK_SIZE);
    memcpy(padded, data, len);
    if (len < AES_BLOCK_SIZE) {
        padded[len] = 0x80;  // Add padding bit
    }
}


