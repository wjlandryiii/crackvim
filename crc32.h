/*
 * Coped from RFC2083
 */

#ifndef CRC32_H
#define CRC32_H

extern unsigned long crc_table[256];
extern int crc_table_computed;

void make_crc_table(void);
unsigned long update_crc(unsigned long crc, unsigned char *buf, int len);
unsigned long crc(unsigned char *buf, int len);

#endif
