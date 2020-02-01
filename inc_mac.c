
#include <EverCrypt_AEAD.h>

#include "inc_mac.h"

EverCrypt_Error_error_code
init_inc_mac(
  inc_mac_state_s** inc_mac_state,
  uint8_t* key,
  uint32_t h_table_size,
  uint32_t length_table_size
)
{
  uint8_t scratch[BLOCK_LEN] = { 0U };
  EverCrypt_Error_error_code ret;

  EverCrypt_AutoConfig2_init();

  Spec_Agile_AEAD_alg alg = Spec_Agile_AEAD_AES128_GCM;

  *inc_mac_state = calloc(1, sizeof(inc_mac_state_s));
  if (*inc_mac_state == NULL) {
    return 1;
  }
  (*inc_mac_state)->h_table = calloc(h_table_size, BLOCK_LEN);
  if ((*inc_mac_state)->h_table == NULL) {
    return 2;
  }
  (*inc_mac_state)->length_table = calloc(length_table_size, BLOCK_LEN);
  if ((*inc_mac_state)->length_table == NULL) {
    return 3;
  }

  ret = EverCrypt_AEAD_create_in(alg, &((*inc_mac_state)->aead_state), key);
  if (ret) {
    free(inc_mac_state);
    return ret;
  }

  uint8_t *hkeys_b = (*inc_mac_state)->aead_state->ek + (uint32_t)176U;

  // copy h to h_table[0]
  memcpy((*inc_mac_state)->h_table, hkeys_b, GHASH_LEN);

  // fill remaining h_table entries
  for (uint32_t i = 1; i < h_table_size; ++i) {
    ghash_register(
      (*inc_mac_state)->h_table +     i * GHASH_LEN,
      (*inc_mac_state)->h_table + (i-1) * GHASH_LEN,
      hkeys_b
    );
  }

  for (uint32_t content_len=0; content_len < length_table_size; ++content_len) {
    uint8_t length[BLOCK_LEN] = { 0U };

    *(((uint64_t*) length) + 1) = content_len * 8;
    store128_le(scratch, (uint128_t) 0);
    ghash_register(length, scratch, (*inc_mac_state)->h_table);
    uint128_t tmp = load128_le(length);
    store128_be((*inc_mac_state)->length_table + content_len * BLOCK_LEN, tmp);
  }

  return ret;
}

void
free_inc_mac(
  inc_mac_state_s* inc_mac_state
)
{
  EverCrypt_AEAD_free(inc_mac_state->aead_state);
  free(inc_mac_state->h_table);
  free(inc_mac_state);
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

void
compute_inc_mac(
  inc_mac_state_s* inc_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_block, // will be overwritten with the ghash
  uint32_t change_block_idx,
  uint8_t* tag
)
{
  uint32_t nb_blocks = (content_len >> 4) + 1;
  EverCrypt_AEAD_state_s* aead_state = inc_mac_state->aead_state;
  uint8_t ctr_block[BLOCK_LEN] = { 0U };
  uint8_t scratch[BLOCK_LEN] = { 0U };
  uint8_t *length, *ghash, *h, *prev_ghash;
  uint128_t tmp;

  prev_ghash = inc_mac_state->prev_ghash;

  memcpy(ctr_block, iv, IV_LEN);
  tmp = load128_be(ctr_block) + 1;
  store128_le(ctr_block, tmp);

  uint32_t htable_idx = nb_blocks - change_block_idx - 1;

  h = inc_mac_state->h_table + BLOCK_LEN * htable_idx;

  ghash_register_reverse_input(prev_block, content + change_block_idx * BLOCK_LEN, h);

  store128_le(scratch, (uint128_t) 0);
  *(((uint64_t*) scratch) + 1) = content_len * 8; // length 
  h = inc_mac_state->h_table;
  ghash_register(prev_block, scratch, h);

  length = inc_mac_state->length_table + BLOCK_LEN * content_len;

  ghash = prev_block;
  tmp = load128_be(prev_block) ^ load128_le(length) ^ load128_le(prev_ghash);
  store128_le(ghash, tmp);
  
  // compute AES(IV') ^ ghash
  gctr128_bytes(
    ghash,
    (uint64_t)16U,
    tag,
    scratch,
    aead_state->ek,
    ctr_block,
    1U
  );
}
