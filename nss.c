
#include <stdlib.h>

#include "nss.h"

int init_nss(gcm_context_s** gctx, uint8_t* key, uint8_t* iv)
{
    *gctx = calloc(1, sizeof(gcm_context_s));
    if (*gctx == NULL) {
        return 1;
    }
    (*gctx)->ks = calloc(1, sizeof(key_schedule_s));
    if ((*gctx)->ks == NULL) {
        free(*gctx);
        return 2;
    }

    intel_aes_encrypt_init_128(key, (*gctx)->ks->ks);
    (*gctx)->ks->nr = 10;
    
    intel_aes_gcmINIT((*gctx)->htbl, (*gctx)->ks->ks, (*gctx)->ks->nr);

    nss_refresh(*gctx, iv);

    return 0;
}

void free_nss(gcm_context_s* gctx)
{
    free(gctx->ks);
    free(gctx);
}

void nss_refresh(gcm_context_s* gctx, uint8_t* iv)
{
    uint8_t scratch[BLOCK_LEN] = { 0U };

    memcpy(gctx->ctr, iv, IV_LEN);

    intel_aes_gcmENC(scratch, gctx->x0, gctx, BLOCK_LEN);
    memset(gctx->t, 0, BLOCK_LEN);
}

void mac_nss(
    gcm_context_s* gctx,
    uint8_t* content,
    uint64_t content_len,
    uint8_t* tag,
    uint8_t* iv
)
{
    uint8_t scratch[BLOCK_LEN] = { 0U };
    uint64_t partial = content_len % BLOCK_LEN;
    uint64_t first_content_len = content_len - partial;

    nss_refresh(gctx, iv);

    if (partial) {
        memcpy(scratch, content + first_content_len, partial);
    }
    intel_aes_gcmAAD(gctx->htbl, content, first_content_len, gctx->t);
    if (partial) {
        intel_aes_gcmAAD(gctx->htbl, scratch, BLOCK_LEN, gctx->t);
    }
    intel_aes_gcmTAG(gctx->htbl, gctx->t, 0, content_len, gctx->x0, tag);
}
