#ifndef INC_CRC_H_
#define INC_CRC_H_
#include <stdint.h>

extern const uint16_t CrcTable[256];
uint16_t fCrcBlk(uint8_t *pData, uint16_t nLength);

#endif /* INC_CRC_H_ */
