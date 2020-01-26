
#ifndef _INC_MAC_H
#define _INC_MAC_H

#include <EverCrypt_AEAD.h>

#define KEY_LEN   16 // 128 bits
#define IV_LEN    12 // 96 bits
#define TAG_LEN   16 // 128 bits
#define GHASH_LEN 16 // 128 bits

typedef struct inc_mac_state_s_s
{
  EverCrypt_AEAD_state_s* aead_state;
  uint8_t prev_ghash[GHASH_LEN];
}
inc_mac_state_s;

EverCrypt_Error_error_code
init_inc_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* key
);

void free_inc_mac(inc_mac_state_s* inc_mac_state);

void
compute_first_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* tag
);

void
compute_inc_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* tag,
  uint32_t change_byte
);

// a and b are 128-bit values
// h_table is initalized during create_in and lives inside EverCrypt_AEAD_state_s
// computes: a <- (a xor b) * h
extern void ghash_register(uint8_t* a, uint8_t* b, uint8_t* h_table);

#endif // _INC_MAC_H
