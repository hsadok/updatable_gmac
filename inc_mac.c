
#include <EverCrypt_AEAD.h>

#include "inc_mac.h"

EverCrypt_Error_error_code
init_inc_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* key
)
{
  EverCrypt_Error_error_code ret;

  EverCrypt_AutoConfig2_init();

  Spec_Agile_AEAD_alg alg = Spec_Agile_AEAD_AES128_GCM;
  ret = EverCrypt_AEAD_create_in(alg, &(inc_mac_state->aead_state), key);
  
  return ret;
}

void
free_inc_mac(
  inc_mac_state_s* inc_mac_state
)
{
  EverCrypt_AEAD_free(inc_mac_state->aead_state);
}

void
compute_first_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* tag
)
{
  encrypt_aes128_gcm_save_ghash(
    inc_mac_state->aead_state,
    iv,
    IV_LEN,
    content,
    content_len,
    NULL, // no plain data
    0,    // no plain data
    NULL, // we don't care about the encrypted output
    tag,
    inc_mac_state->prev_ghash
  );
}

// void
// compute_inc_mac(
//   inc_mac_state_s* inc_mac_state,
//   uint8_t* iv,
//   uint8_t *content,
//   uint32_t content_len,
//   uint8_t* tag,
//   uint32_t change_byte
// )
// {
//   // uint32_t change_block_idx = change_byte >> 4; // 128-bit blocks
//   EverCrypt_AEAD_state_s* aead_state = inc_mac_state->aead_state;
//   uint8_t *hkeys_b = aead_state->ek + (uint32_t)176U;
  
//   ghash_register(block_a, block_b, h_table[n-i]);
//   ghash_register(block_a, length, h_table[n]);

// }
