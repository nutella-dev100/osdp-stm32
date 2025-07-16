/*
 * rand.h
 *
 *  Created on: Jun 24, 2025
 *      Author: Admin
 */

#ifndef INC_RAND_H_
#define INC_RAND_H_

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "stm32f7xx_hal.h"
#include "main.h"

extern RNG_HandleTypeDef hrng;

void gen_random_bytes(uint8_t* buf);

#endif /* INC_RAND_H_ */
