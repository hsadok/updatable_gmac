
#ifndef _UPD_MAC_H
#define _UPD_MAC_H

#include <EverCrypt_AEAD.h>

#define KEY_LEN   16 // 128 bits
#define IV_LEN    12 // 96 bits
#define TAG_LEN   16 // 128 bits
#define BLOCK_LEN 16 // 128 bits
#define GHASH_LEN 16 // 128 bits

typedef struct upd_mac_state_s_s
{
  EverCrypt_AEAD_state_s* aead_state;
  uint8_t* h_table;
  uint8_t* length_table;
}
upd_mac_state_s;

EverCrypt_Error_error_code
init_upd_mac_with_callbacks(
  upd_mac_state_s** upd_mac_state,
  uint8_t* key,
  uint32_t h_table_size,
  uint32_t length_table_size,
  void* (*malloc_ptr)(size_t),
  void (*free_ptr)(void*)
);

void free_upd_mac(upd_mac_state_s* upd_mac_state);

void
compute_first_mac(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t* content,
  uint32_t content_len,
  uint8_t* ghash,
  uint8_t* tag
);

void
compute_upd_mac(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t* content,
  uint64_t content_len,
  uint8_t* prev_block,
  uint32_t change_block_idx,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_mult_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_2_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_3_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_mult_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // array of all previous blocks (the array is
                        // contiguous, even though the blocks may not be)
  uint32_t* change_block_idxes,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_2_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // array of all previous blocks (the array is
                        // contiguous, even though the blocks may not be)
  uint32_t* change_block_idxes,
  uint8_t* prev_ghash,
  uint8_t* tag
);

void
compute_upd_mac_3_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint64_t content_len,
  uint8_t* prev_blocks, // array of all previous blocks (the array is
                        // contiguous, even though the blocks may not be)
  uint32_t* change_block_idxes,
  uint8_t* prev_ghash,
  uint8_t* tag
);

// a and b are 128-bit values
// h_table is initalized during create_in and lives inside EverCrypt_AEAD_state_s
// computes: a <- (a xor b) * h
extern void ghash_register(
  uint8_t* a,
  const uint8_t* b,
  const uint8_t* h_table
);

extern void double_ghash_register(
  uint8_t* a,
  const uint8_t* b,
  const uint8_t* h_k,
  const uint8_t* h_1,
  uint64_t content_len
);

#endif // _UPD_MAC_H
