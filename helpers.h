
#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdlib.h>

#include <EverCrypt_AEAD.h>


#define H_TABLE_SIZE 100
#define LENGTH_TABLE_SIZE 1501

#define MESSAGE_LEN 20

static const uint8_t ref_key[KEY_LEN] = {
    0x2f, 0xb4, 0x5e, 0x5b, 0x8f, 0x99, 0x3a, 0x2b,
    0xfe, 0xbc, 0x4b, 0x15, 0xb5, 0x33, 0xe0, 0xb4
};
static const uint8_t ref_iv[IV_LEN] = {
    0x5b, 0x05, 0x75, 0x5f, 0x98, 0x4d, 0x2b, 0x90,
    0xf9, 0x4b, 0x80, 0x27
};
static const uint8_t ref_message[MESSAGE_LEN] = {
    0xe8, 0x54, 0x91, 0xb2, 0x20, 0x2c, 0xaf, 0x1d,
    0x7d, 0xce, 0x03, 0xb9, 0x7e, 0x09, 0x33, 0x1c,
    0x32, 0x47, 0x39, 0x41
};
static const uint8_t expected_tag[TAG_LEN] = {
    0xc7, 0x5b, 0x78, 0x32, 0xb2, 0xa2, 0xd9, 0xbd,
    0x82, 0x74, 0x12, 0xb6, 0xef, 0x57, 0x69, 0xdb
};

#define MIN(a,b) (((a)<(b))?(a):(b))

void print_hex_vector(const uint8_t* vector, size_t size);

int compare_tags(const uint8_t tag1[TAG_LEN], const uint8_t tag2[TAG_LEN],
                 bool verbose);

uint8_t* get_extended_message(uint16_t extended_message_len);

void get_ref_values(uint8_t* key, uint8_t* iv, uint8_t* message);

EverCrypt_Error_error_code
init_upd_mac(
  upd_mac_state_s** upd_mac_state,
  uint8_t* key,
  uint32_t h_table_size,
  uint32_t length_table_size
);

#endif // _HELPERS_H
