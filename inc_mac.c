
#include <EverCrypt_AEAD.h>

#include "inc_mac.h"

static void print_hex_vector(uint8_t* vector, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx ", vector[i]);
    }
    printf("\n");
}

EverCrypt_Error_error_code
init_inc_mac(
  inc_mac_state_s** inc_mac_state,
  uint8_t* key,
  uint32_t htable_size
)
{
  EverCrypt_Error_error_code ret;

  EverCrypt_AutoConfig2_init();

  Spec_Agile_AEAD_alg alg = Spec_Agile_AEAD_AES128_GCM;

  *inc_mac_state = calloc(1, sizeof(inc_mac_state_s) + htable_size * BLOCK_LEN);
  if (*inc_mac_state == NULL) {
    return 1;
  }

  (*inc_mac_state)->htable_size = htable_size;

  ret = EverCrypt_AEAD_create_in(alg, &((*inc_mac_state)->aead_state), key);
  if (ret) {
    free(inc_mac_state);
    return ret;
  }

  uint8_t *hkeys_b = (*inc_mac_state)->aead_state->ek + (uint32_t)176U;

  // copy h to h_table[0]
  memcpy((*inc_mac_state)->h_table, hkeys_b, GHASH_LEN);

  // fill remaining h_table entries
  for (uint32_t i = 1; i < htable_size; ++i) {
    ghash_register(
      (*inc_mac_state)->h_table +     i * GHASH_LEN,
      (*inc_mac_state)->h_table + (i-1) * GHASH_LEN,
      hkeys_b
    );
  }

  return ret;
}

void
free_inc_mac(
  inc_mac_state_s* inc_mac_state
)
{
  EverCrypt_AEAD_free(inc_mac_state->aead_state);
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
  uint8_t* prev_block,
  uint32_t change_block_idx,
  uint8_t* tag
)
{
  uint32_t nb_blocks = (content_len >> 4) + 1;
  EverCrypt_AEAD_state_s* aead_state = inc_mac_state->aead_state;
  // uint8_t *hkeys_b = aead_state->ek + (uint32_t)176U;
  uint8_t ctr_block[BLOCK_LEN] = { 0U };
  uint8_t inout_b[BLOCK_LEN] = { 0U };
  uint8_t aes_block[BLOCK_LEN];
  uint8_t length[BLOCK_LEN] = { 0U };
  uint8_t* ghash;
  uint8_t* h;
  uint128_t tmp;

  memcpy(ctr_block, iv, IV_LEN);
  tmp = load128_be(ctr_block) + 1; // TODO(sadok) CHECK if counter should really be 1
  store128_le(ctr_block, tmp); // ok

  printf("ctr_block: ");
  print_hex_vector(ctr_block, sizeof ctr_block);

  // *((uint64_t*) length + 1)= (uint64_t) content_len;
  tmp = load128_be(length) + content_len;
  store128_le(length, tmp);

  printf("length: ");
  print_hex_vector(length, sizeof length);
  
  uint32_t htable_idx = nb_blocks - change_block_idx - 1;
  printf("h_table[%u]\n", htable_idx);
  h = inc_mac_state->h_table + BLOCK_LEN * htable_idx;

  // tmp = load128_be(prev_block);
  // store128_le(prev_block, tmp);

  // tmp = load128_be(content + change_block_idx * BLOCK_LEN);
  // store128_le(content + change_block_idx * BLOCK_LEN, tmp);
  
  ghash_register(prev_block, content + change_block_idx * BLOCK_LEN, h);

  h = inc_mac_state->h_table;
  ghash = prev_block;
  ghash_register(ghash, length, h);

  printf("ghash: ");
  print_hex_vector(ghash, GHASH_LEN);

  tmp = load128_be(ghash);
  store128_le(ghash, tmp);
  
  // compute AES(IV') ^ ghash
  gctr128_bytes(
    ghash,
    (uint64_t)16U,
    aes_block,
    inout_b,
    aead_state->ek,
    ctr_block,
    1U
  );
  printf("aes block: ");
  print_hex_vector(aes_block, BLOCK_LEN);

  tmp = load128_be(inc_mac_state->prev_ghash) ^ load128_be(aes_block);
  store128_le(tag, tmp);

  // __m128i tmp = _mm_xor_si128(
  //   _mm_loadu_si128((__m128i*) inc_mac_state->prev_ghash),
  //   _mm_loadu_si128((__m128i*) aes_block)
  // );
  // _mm_storeu_si128((__m128i*) tag, tmp);
}
