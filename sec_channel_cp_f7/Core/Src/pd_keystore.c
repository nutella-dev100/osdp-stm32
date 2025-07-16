#include "pd_keystore.h"

#define MAX_PD 32

typedef struct{
	uint64_t cuid;
	uint8_t master_key[16];
	uint8_t active;
}pd_entry;

int curr_idx = 0;
static pd_entry keystore[MAX_PD];	//array of pd_entry

bool pd_keystore_init(void){
	memset(keystore, 0, sizeof(keystore));
	curr_idx = 0;
	return true;
}

bool pd_keystore_add(uint64_t cuid, const uint8_t* master_key){

	if(curr_idx >= MAX_PD)
		return false;

	for(int i = 0; i < MAX_PD; i++){
		if(keystore[i].cuid == cuid){
			return false;
		}
	}

	keystore[curr_idx].cuid = cuid;
	memcpy(keystore[curr_idx].master_key, master_key, 16);
	keystore[curr_idx].active = 1;
	curr_idx++;
	return true;
}

uint8_t* pd_keystore_get(uint64_t cuid){
	for(int i = 0; i < curr_idx; i++){
		if(keystore[i].cuid == cuid && keystore[i].active){
			return keystore[i].master_key;
		}
	}
	return NULL;
}

bool pd_keystore_remove(uint64_t cuid){
	for(int i = 0; i < curr_idx; i++){
		if(keystore[i].cuid == cuid && keystore[i].active){
			keystore[i].cuid = 0;
			memset(keystore[i].master_key, 0, 16);
			keystore[i].active = 0;
			return true;
		}
	}
	return false;
}
