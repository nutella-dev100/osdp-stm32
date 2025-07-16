/*
 * pd_keystore.h
 *
 *  Created on: Jun 24, 2025
 *      Author: Admin
 */

#ifndef INC_PD_KEYSTORE_H_
#define INC_PD_KEYSTORE_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

bool pd_keystore_init(void);
bool pd_keystore_add(uint64_t cuid, const uint8_t* master_key);
uint8_t* pd_keystore_get(uint64_t cuid);
bool pd_keystore_remove(uint64_t cuid);
#endif /* INC_PD_KEYSTORE_H_ */
