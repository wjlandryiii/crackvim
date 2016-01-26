/*
 * Copyright 2016 Joseph Landry All Rights Reserved
 */

#include <stdint.h>

#include "crc32.h"

void update_key(uint32_t key[3], uint8_t c){
	key[0] = crc_table[(key[0] ^ c) & 0xff] ^ (key[0]>>8);
	key[1] = key[1] + (key[0] & 0xff);
	key[1] = key[1] * 134775813 + 1;
	key[2] = crc_table[(key[2] ^ (key[1] >> 24)) & 0xff] ^ (key[2]>>8);
}

void init_key(uint32_t key[3], char *password){
	char *p;

	p = password;
	key[0] = 305419896;
	key[1] = 591751049;
	key[2] = 878082192;

	while(*p){
		update_key(key, *p++);
	}
}

uint8_t decrypt_byte(uint32_t key[3]){
	uint16_t tmp;

	tmp = key[2] | 2;
	return (tmp * (tmp ^ 1)) >> 8;
}

void pkzip_decrypt(uint32_t key[3], const uint8_t *ciphertext, long length, uint8_t *out_plaintext){
	uint8_t c;
	const uint8_t *stop = ciphertext + length;
	while(ciphertext < stop){
		c = *ciphertext++ ^ decrypt_byte(key);
		update_key(key, c);
		*out_plaintext++ = c;
	}
}
