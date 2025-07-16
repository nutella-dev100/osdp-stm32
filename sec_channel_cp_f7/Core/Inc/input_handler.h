/*
 * input_handler.h
 *
 *  Created on: Jul 9, 2025
 *      Author: Admin
 */

#ifndef INC_INPUT_HANDLER_H_
#define INC_INPUT_HANDLER_H_

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "crc.h"
#include "osdp_packet.h"
#include "main.h"
#include "aes.h"

void inputHandler(UART_HandleTypeDef *huart, uint16_t Size);
void scs12handler();
void scs14handler();
void scs16handler(uint16_t Size);
void scs18handler(uint16_t Size);
int verify_mac(uint16_t Size);

#endif /* INC_INPUT_HANDLER_H_ */
