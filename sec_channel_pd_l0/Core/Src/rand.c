/*
 * rand.c
 *
 *  Created on: Jun 24, 2025
 *      Author: Admin
 */

#include "rand.h"

void gen_random_bytes(uint8_t* buf){
	uint32_t random_word1, random_word2;
	HAL_RNG_GenerateRandomNumber(&hrng, &random_word1);
	HAL_RNG_GenerateRandomNumber(&hrng, &random_word2);

	memcpy(buf, &random_word1, 4);
	memcpy(buf + 4, &random_word2, 4);
}

