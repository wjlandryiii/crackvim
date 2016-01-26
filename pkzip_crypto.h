/*
 * Copyright 2016 Joseph Landry All Rights Reserved
 */

#ifndef PKZIP_CRYPTO_H
#define PKZIP_CRYPTO_H

void update_key(uint32_t key[3], uint8_t c);
void init_key(uint32_t key[3], char *password);
uint8_t decrypt_byte(uint32_t key[3]);
void pkzip_decrypt(uint32_t key[3], const uint8_t *ciphertext, long length, uint8_t *out_plaintext);

#endif
