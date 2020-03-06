
#ifndef _NSS_H
#define _NSS_H

#include "upd_mac.h"

#define AES_MAX_EXP_KEY_SIZE 8*15

typedef struct key_schedule_s_s
{
  uint32_t _nb;
  uint32_t nr;
  void (*_freebl_cipher_func)(void);
  uint8_t _iv[BLOCK_LEN*2];
  uint32_t ks[AES_MAX_EXP_KEY_SIZE];
}
key_schedule_s;

typedef struct gcm_context_s_s
{
  uint8_t htbl[16 * BLOCK_LEN];
  uint8_t x0[BLOCK_LEN];
  uint8_t t[BLOCK_LEN];
  uint8_t ctr[BLOCK_LEN];
  key_schedule_s* ks;
}
gcm_context_s;

extern void intel_aes_encrypt_init_128(uint8_t* key, uint32_t* ks);

extern void intel_aes_gcmINIT(uint8_t* htbl, uint32_t* ks, uint32_t nr);

extern void intel_aes_gcmENC(
  uint8_t* pt,
  uint8_t* ct,
  gcm_context_s* gctx,
  uint64_t content_len
);

extern void intel_aes_gcmAAD(
  uint8_t* htbl,
  uint8_t* content,
  uint64_t content_len,
  uint8_t* t
);

extern void intel_aes_gcmTAG(
  uint8_t* htbl,
  uint8_t* t,
  uint64_t m_len,
  uint64_t a_len,
  uint8_t* x0,
  uint8_t* tag
);

int init_nss(gcm_context_s** gctx, uint8_t* key, uint8_t* iv);

void free_nss(gcm_context_s* gctx);

void nss_refresh(gcm_context_s* gctx, uint8_t* iv);

void mac_nss(
  gcm_context_s* gctx,
  uint8_t* content,
  uint64_t content_len,
  uint8_t* tag,
  uint8_t* iv
);

#endif // _NSS_H
