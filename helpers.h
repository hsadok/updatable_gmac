
#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdlib.h>

#include <EverCrypt_AEAD.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / \
                    ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#define H_TABLE_SIZE 100
#define LENGTH_TABLE_SIZE 1501

// static const uint8_t ref_key[KEY_LEN] = {
//     0x2f, 0xb4, 0x5e, 0x5b, 0x8f, 0x99, 0x3a, 0x2b,
//     0xfe, 0xbc, 0x4b, 0x15, 0xb5, 0x33, 0xe0, 0xb4
// };
// static const uint8_t ref_iv[IV_LEN] = {
//     0x5b, 0x05, 0x75, 0x5f, 0x98, 0x4d, 0x2b, 0x90,
//     0xf9, 0x4b, 0x80, 0x27
// };
// static const uint8_t ref_message[] = {
//     0xe8, 0x54, 0x91, 0xb2, 0x20, 0x2c, 0xaf, 0x1d,
//     0x7d, 0xce, 0x03, 0xb9, 0x7e, 0x09, 0x33, 0x1c,
//     0x32, 0x47, 0x39, 0x41
// };
// static const uint8_t expected_tag[TAG_LEN] = {
//     0xc7, 0x5b, 0x78, 0x32, 0xb2, 0xa2, 0xd9, 0xbd,
//     0x82, 0x74, 0x12, 0xb6, 0xef, 0x57, 0x69, 0xdb
// };

// static const uint8_t ref_key[KEY_LEN] = {
//     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
//     0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
// };
// static const uint8_t ref_iv[IV_LEN] = {
//     0x00, 0x01, 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
//     0x00, 0x00, 0x00, 0x00
// };
// static const uint8_t ref_message[] = {
//     0x45, 0x00, 0x00, 0x34, 0x08, 0x85, 0x40, 0x00,
//     0x40, 0x06, 0x20, 0x93, 0x0a, 0x00, 0x00, 0x2e,
//     0x51, 0x5f, 0xb6, 0x1f, 0xaf, 0x32, 0x9f, 0xba,
//     0xe4, 0x91, 0xa4, 0x16, 0x6b, 0xf0, 0x5b, 0x0f,
//     0x80, 0x10, 0x1d, 0x46, 0x6e, 0x91, 0x00, 0x00,
//     0x01, 0x01, 0x08, 0x0a, 0x00, 0x78, 0x48, 0x07,
//     0x6b, 0xdb, 0x86, 0x49, 0x00, 0x01, 0xca, 0xfe,
//     0xba, 0xbe, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x01, 0x00,
// };

// static const uint8_t expected_tag[TAG_LEN] = {
//     0xc6, 0x71, 0x66, 0xc8, 0x4b, 0x20, 0xb7, 0xa0,
//     0xde, 0x10, 0x86, 0xb7, 0x5a, 0x13, 0x87, 0xc5
// };

static const uint8_t ref_key[KEY_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};

static const uint8_t ref_iv[IV_LEN] = {
    0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
    0x00, 0x00, 0x00, 0x00
};

static const uint8_t ref_message[] = {
    0x45,  0x0,  0x2, 0xF1,  0xA, 0xB7,  0x0,  0x0, 0x70, 0x11,
    0xE3, 0x1A, 0x80, 0xED, 0xCF,  0xF,  0xA,  0x0,  0x0, 0x2E,
    0x80, 0xC6, 0xE7, 0xEA,  0x2, 0xDD, 0xA0, 0x94,  0x1,  0x0,
    0xF1, 0xDB, 0x1F, 0xDE, 0xCC,  0xC, 0xA8,  0x7, 0x8D, 0xBD,
     0x0,  0x0, 0xF0,  0x0, 0xAA, 0x8F, 0x16, 0xF5, 0xD0, 0xDE,
    0x1E,  0x0,  0x0, 0x72, 0x63, 0xE6, 0x7B, 0xBD, 0x31, 0x28,
    0x2C, 0x53, 0x41,  0xD, 0xA0, 0x4D, 0x43, 0x41, 0xEF, 0xBB,
    0x8D, 0x9D, 0x61, 0x20,  0xC, 0xC4,  0x3, 0x77, 0xD6, 0xA0,
    0x2C, 0xA9, 0xCB, 0xDF, 0x62, 0xFA, 0xE7, 0x60, 0xC0, 0x51,
     0x5, 0x32, 0x75, 0x5C, 0x22, 0xFC, 0x46, 0xD3, 0xF6, 0xF5,
    0xA0, 0xDD, 0x58, 0xA2, 0x72, 0xE8, 0x20, 0xF9, 0x9F,  0x2,
    0xC7, 0xCD, 0x30, 0x7C, 0x2E, 0x88, 0x62, 0xD4, 0xE0, 0xFF,
    0x29, 0x74, 0xF0, 0x55, 0x71, 0xDC, 0xBB, 0xCB, 0x8C, 0xD0,
    0x77, 0xA1, 0xB3, 0xE4, 0x76, 0x61, 0x42, 0x2B, 0xB3, 0xEA,
    0xF9, 0x52,  0x1, 0xD1, 0x30, 0x87, 0x35, 0x62, 0x35, 0xF1,
    0x67, 0x30, 0x6C, 0x97, 0xA7, 0x22, 0x78, 0x68, 0x67, 0xC3,
    0xE4, 0x58, 0xAB, 0xF0, 0xA0, 0x53, 0xA6, 0x31, 0x36, 0x4A,
    0x52, 0xD2, 0x2C, 0x8C, 0x22, 0x9B, 0xE7, 0x90, 0x19, 0xDF,
     0x3, 0x23, 0x40, 0x63, 0x45, 0x95,  0x0, 0x2D, 0x5F, 0x8E,
    0x8D, 0x71, 0x62, 0xFB, 0x31, 0x44, 0xE5, 0x41, 0x77, 0x7E,
    0x5E, 0x6E, 0xFD, 0x74, 0x1C, 0x66, 0x37, 0xC1, 0x66, 0x99,
     0x3, 0x10,  0x7, 0x3E, 0xF1, 0xEE, 0x49, 0x10, 0x4C, 0x6B,
    0x12,  0xB, 0x2A, 0x31, 0xA3, 0x2C, 0x14, 0x28, 0x11,  0x5,
    0x3F, 0x94, 0x80, 0xAB, 0xA4,  0x6, 0x1D, 0xC4, 0x59, 0x62,
    0x16, 0x5B, 0xC6, 0xED, 0xFF, 0x59, 0x18, 0x7E, 0x89,  0x8,
    0x7A, 0xE6, 0x98, 0x2C, 0xC2, 0x28, 0x9E, 0x88, 0xAD, 0xD9,
    0x9F, 0x8E, 0x5B,  0x6, 0x70, 0xA5, 0xE3,  0xF, 0x92, 0xC1,
    0x8A, 0xC1, 0x98, 0x4E, 0x19, 0x92, 0xFF, 0x38, 0xA6, 0x7C,
    0xA9, 0x52, 0x50, 0xB6, 0x35, 0x85, 0xE8, 0x1E, 0xB1, 0x4B,
    0xF4, 0xBC, 0x14, 0x6E, 0xC0, 0xC5, 0xE9, 0xE4, 0xA4, 0xF3,
    0xBF, 0xD5, 0x4E, 0x72, 0xB6, 0xE7, 0x68, 0x91, 0xF6, 0xCD,
    0x7F, 0xD5, 0x32, 0x3F, 0xE2, 0x62, 0x1B, 0xDA, 0xC8, 0xDF,
     0x5, 0xAC, 0x78, 0xEF, 0xBE, 0xCB, 0xE7, 0x82, 0xC1, 0xC8,
    0xAA, 0xAA, 0xE0, 0x1E, 0xA4, 0xAC, 0x9C, 0x37, 0x27, 0x8D,
    0xDA, 0x2E, 0x9E, 0x50, 0xFC, 0x87, 0x3C, 0xB6,  0xA, 0x41,
    0xFB,  0xB, 0x3D, 0xD4, 0x4E, 0x53, 0x6A, 0x2E, 0x7D, 0x39,
    0xBD, 0x90, 0x26,  0x4, 0xBA, 0xC5, 0xC7, 0x9F, 0x66, 0x2E,
    0xE2, 0x74, 0x4A, 0xD2, 0xF9, 0x2A, 0x44, 0xFF, 0x7D, 0x53,
     0x2, 0xCD,  0x0, 0xAE, 0xEC, 0xC0,  0x0, 0x6E, 0x61, 0x81,
    0xFC, 0x9A, 0x66, 0xF4, 0x2E,  0x1, 0xC9, 0x7F, 0x29, 0x3C,
    0x3D, 0x66,  0x4, 0xDC, 0xDA, 0x82, 0xC8, 0x8D, 0xEB, 0x8E,
    0x30, 0xE7, 0xD0, 0x77, 0xD5, 0x5C, 0x23, 0xC7, 0x7C, 0x9C,
    0x32, 0xE1, 0x1C, 0xF1, 0xCA, 0x2A, 0x11, 0xAA, 0x5D, 0x3C,
    0xC7, 0xE1, 0x9A, 0xA3, 0x28,  0x0, 0x2F, 0xA9, 0xE7, 0xB3,
    0xAB, 0x38, 0x80, 0x1F, 0x24, 0x54, 0x15, 0x44, 0x50, 0xF6,
    0x5A, 0x68, 0x3C, 0xFF, 0x14, 0xAD, 0xF2, 0x5F, 0xEB, 0x2D,
    0x13, 0x10, 0x12, 0xD4, 0xEA, 0x76, 0xE0, 0x7B, 0xBD, 0x33,
    0x47, 0x90, 0xB7, 0x2B, 0x16, 0xB1, 0xF9, 0x74, 0x7B, 0xB2,
    0x2D, 0x38, 0x6A, 0xA8, 0x17, 0x47, 0x43, 0x90, 0xB5, 0x5B,
    0xA0, 0x59, 0xAD, 0x31, 0xBC, 0x72, 0x39, 0x8C,  0x5, 0x93,
    0x14, 0xA4, 0x90, 0xBA, 0xBC, 0x24, 0x2D, 0xC8, 0xC8, 0xEA,
    0x21, 0xB5, 0xF3, 0xCC, 0x31, 0x50, 0xC8, 0x8B, 0xA9, 0x86,
    0x73, 0x34, 0x6F, 0x13, 0xB1, 0x24, 0xAD, 0x44, 0x76, 0xD7,
    0x18, 0xF8, 0x21, 0x25, 0xDF, 0x2F, 0xF1, 0x9A, 0x1A, 0xC8,
    0x88, 0xB9, 0xDF, 0xED, 0x70, 0xB6, 0x27,  0x4,  0x1, 0xCC,
    0x9C, 0xA1, 0x48, 0x22, 0xAE, 0x32, 0x11, 0x62, 0xE2, 0x67,
    0xA3,  0x5, 0x58, 0x66, 0x69, 0x88, 0x88, 0xA2, 0x36, 0xD1,
    0x1C, 0x2D, 0x76, 0x56, 0x1B, 0x20,  0x1, 0xB6, 0x7F, 0xCC,
    0xBF, 0xF0,  0x8, 0x1F, 0x99, 0x60, 0x24, 0xAB, 0x7A, 0x2F,
    0xD1, 0x97, 0x80,  0x2, 0x12, 0x42, 0x6A, 0x93, 0xE3, 0x27,
     0x7,  0x7, 0xFA, 0xE5,  0xF, 0x79, 0xDB, 0xA4, 0xB9, 0xB2,
    0x9F, 0x2A, 0x47, 0x58, 0x16, 0xFA, 0x90, 0x48, 0x5D, 0x45,
    0xB7, 0x33, 0x22, 0x4D, 0x2A, 0xC2, 0x12, 0xBF, 0xA3, 0x25,
    0x5D, 0x93, 0xC3, 0x5F,  0x4, 0x37, 0xDE, 0x17, 0xBF, 0x26,
    0xB8, 0x26, 0xD2, 0x86, 0x8B, 0x18, 0xB5, 0xB9, 0x89, 0x51,
    0xBA, 0x8E, 0x7A, 0x9D, 0x79, 0x68, 0xFC, 0x14, 0x14, 0xF9,
    0x9E, 0xB0, 0x55, 0xBE, 0xB2, 0x2F, 0x71, 0xDC, 0x2E, 0x58,
    0x98, 0x83, 0x6C, 0x50, 0xC6, 0x43, 0x72, 0xAF, 0xB6, 0x69,
    0x86, 0xD8, 0xF7, 0x61, 0xF3, 0x3E, 0xF8, 0xE0, 0xF6, 0x67,
    0xAC, 0x62, 0x34, 0xB8, 0x28, 0xFF, 0x61, 0x4B, 0x45, 0xA2,
     0x9, 0xCF, 0xEA, 0x5C, 0x83, 0x6B,  0xF,  0x5, 0x1F, 0x21,
    0xF2, 0x11, 0x36, 0xD4, 0xD6, 0x7D, 0x26, 0xB0,  0xB, 0x31,
    0x2E, 0xD2, 0x90,  0x3, 0x16, 0x2F, 0xDF, 0x68, 0xB0, 0x89,
    0x3E, 0xCB, 0xBD, 0xB3, 0x79, 0x33, 0x50, 0xD3, 0x1C, 0x3E,
    0x5F, 0x56, 0xD7, 0x77, 0x40, 0xE3, 0xB7, 0x85, 0x7C, 0x7C,
    0xB9, 0xBD, 0x47,  0x0,  0x0, 0xCA, 0xFE, 0xBA, 0xBE, 0xFA,
    0xCE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
};

static const uint8_t expected_tag[TAG_LEN] = {
    0xE2, 0xD, 0xD6, 0x18, 0xAD, 0x9D, 0x74, 0x33,
    0x49, 0x8C, 0x46, 0x76, 0x1A, 0x21, 0xB3, 0x92
};

#define MESSAGE_LEN COUNT_OF(ref_message)

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
