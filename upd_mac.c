
#include <EverCrypt_AEAD.h>

#include "upd_mac.h"

/* The following macros and function were adapted from linux-sgx
 * (https://github.com/intel/linux-sgx)
 */
void
__attribute__((noreturn))
__stack_chk_fail(void)
{
    __builtin_trap();
}

void
__attribute__((noreturn))
__attribute__((visibility ("hidden")))
__stack_chk_fail_local (void)
{
    __stack_chk_fail ();
}

/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
typedef	long word;		/* "word" used for optimal copy speed */

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

#ifdef _TLIBC_USE_INTEL_FAST_STRING_
extern void *_intel_fast_memcpy(void *, void *, size_t);
#endif

/*
 * Copy a block of memory, not handling overlap.
 */
void *
__memcpy(void *dst0, const void *src0, size_t length)
{
	char *dst = (char *)dst0;
	const char *src = (const char *)src0;
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
		goto done;

	if ((dst < src && dst + length > src) ||
	    (src < dst && src + length > dst)) {
        /* backwards memcpy */
		__builtin_trap();
	}

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	/*
	 * Copy forward.
	 */
	t = (long)src;	/* only need low bits */
	if ((t | (long)dst) & wmask) {
		/*
		 * Try to align operands.  This cannot be done
		 * unless the low bits match.
		 */
		if ((t ^ (long)dst) & wmask || length < wsize)
			t = length;
		else
			t = wsize - (t & wmask);
		length -= t;
		TLOOP1(*dst++ = *src++);
	}
	/*
	 * Copy whole words, then mop up any trailing bytes.
	 */
	t = length / wsize;
	TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
	t = length & wmask;
	TLOOP(*dst++ = *src++);
done:
	return (dst0);
}


void *
my_memcpy(void *dst0, const void *src0, size_t length)
{
#ifdef _TLIBC_USE_INTEL_FAST_STRING_
 	return _intel_fast_memcpy(dst0, (void*)src0, length);
#else
	return __memcpy(dst0, src0, length);
#endif
}

#if defined __GNUC__ && defined __GNUC_MINOR_
# define __GNUC_PREREQ__(ma, mi) \
    ((__GNUC__ > (ma)) || (__GNUC__ == (ma) && __GNUC_MINOR__ >= (mi)))
#else
# define __GNUC_PREREQ__(ma, mi) 0
#endif
#if defined(__GNUC__) && __GNUC_PREREQ__(2, 96)
#define __predict_true(exp)	__builtin_expect(((exp) != 0), 1)
#define __predict_false(exp)	__builtin_expect(((exp) != 0), 0)
#else
#define __predict_true(exp)	((exp) != 0)
#define __predict_false(exp)	((exp) != 0)
#endif

void *__memcpy_chk(void *dest, const void *src,
              size_t copy_amount, size_t dest_len)
{
    if (__predict_false(copy_amount > dest_len)) {
        /* TODO: add runtime error massage */
        __builtin_trap();
    }

    return my_memcpy(dest, src, copy_amount);
}
/* end of excerpt adapted from linux-sgx */


void* (*my_malloc)(size_t);
void (*my_free)(void*);

static inline void* my_calloc(size_t nmemb, size_t size)
{
  size_t buffer_sz = nmemb * size;
  uint8_t* ptr = my_malloc(buffer_sz);
  for (size_t i = 0; i < buffer_sz; ++i) {
    ptr[i] = (uint8_t) 0;
  }
  return (void*) ptr;
}

EverCrypt_Error_error_code
init_upd_mac_with_callbacks(
  upd_mac_state_s** upd_mac_state,
  uint8_t* key,
  uint32_t h_table_size,
  uint32_t length_table_size,
  void* (*malloc_ptr)(size_t),
  void (*free_ptr)(void*)
)
{
  uint8_t scratch[BLOCK_LEN] = { 0U };
  EverCrypt_Error_error_code ret;

  my_malloc = malloc_ptr;
  my_free = free_ptr;

  EverCrypt_AutoConfig2_init(malloc_ptr, free_ptr, true);

  Spec_Agile_AEAD_alg alg = Spec_Agile_AEAD_AES128_GCM;

  *upd_mac_state = my_calloc(1, sizeof(upd_mac_state_s));
  if (*upd_mac_state == NULL) {
    return 1;
  }
  (*upd_mac_state)->h_table = my_calloc(h_table_size, BLOCK_LEN);
  if ((*upd_mac_state)->h_table == NULL) {
    return 2;
  }
  (*upd_mac_state)->length_table = my_calloc(length_table_size, BLOCK_LEN);
  if ((*upd_mac_state)->length_table == NULL) {
    return 3;
  }

  ret = EverCrypt_AEAD_create_in(alg, &((*upd_mac_state)->aead_state), key);
  if (ret) {
    my_free(upd_mac_state);
    return ret;
  }

  uint8_t *hkeys_b = (*upd_mac_state)->aead_state->ek + (uint32_t)176U;

  // copy h to h_table[0]
  my_memcpy((*upd_mac_state)->h_table, hkeys_b, GHASH_LEN);

  // fill remaining h_table entries
  for (uint32_t i = 1; i < h_table_size; ++i) {
    ghash_register(
      (*upd_mac_state)->h_table +     i * GHASH_LEN,
      (*upd_mac_state)->h_table + (i-1) * GHASH_LEN,
      hkeys_b
    );
  }

  for (uint32_t content_len=0; content_len < length_table_size; ++content_len) {
    uint8_t length[BLOCK_LEN] = { 0U };

    *(((uint64_t*) length) + 1) = content_len * 8;
    store128_le(scratch, (uint128_t) 0);
    ghash_register(length, scratch, (*upd_mac_state)->h_table);
    uint128_t tmp = load128_le(length);
    store128_be((*upd_mac_state)->length_table + content_len * BLOCK_LEN, tmp);
  }

  return ret;
}

void
free_upd_mac(
  upd_mac_state_s* upd_mac_state
)
{
  EverCrypt_AEAD_free(upd_mac_state->aead_state);
  my_free(upd_mac_state->h_table);
  my_free(upd_mac_state);
}

void
compute_first_mac(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* ghash,
  uint8_t* tag
)
{
  uint32_t nb_blocks = ((content_len-1) >> 4) + 1;
  memset(content + content_len, 0, nb_blocks * 16 - content_len);
  encrypt_aes128_gcm_save_ghash(
    upd_mac_state->aead_state,
    iv,
    IV_LEN,
    content,
    content_len,
    NULL, // no plain data
    0,    // no plain data
    NULL, // we don't care about the encrypted output
    tag,
    ghash
  );
}

void
compute_upd_mac(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_block,
  uint32_t change_block_idx,
  uint8_t* ghash,
  uint8_t* tag
)
{
  uint32_t nb_blocks = ((content_len-1) >> 4) + 1;
  memset(content + content_len, 0, nb_blocks * 16 - content_len);
  EverCrypt_AEAD_state_s* aead_state = upd_mac_state->aead_state;
  uint8_t ctr_block[BLOCK_LEN] = { 0U };
  uint8_t scratch[BLOCK_LEN] = { 0U };
  uint8_t *length;
  uint128_t tmp;

  my_memcpy(ctr_block, iv, IV_LEN);
  tmp = load128_be(ctr_block) + 1;
  store128_le(ctr_block, tmp);

  uint32_t htable_idx = nb_blocks - change_block_idx - 1;

  double_ghash_register(
    prev_block,
    content + change_block_idx * BLOCK_LEN,
    upd_mac_state->h_table + BLOCK_LEN * htable_idx,
    upd_mac_state->h_table,
    content_len
  );

  length = upd_mac_state->length_table + BLOCK_LEN * content_len;

  tmp = load128_le(prev_block) ^ load128_le(length) ^ load128_le(ghash);
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

// use this function when multiple *contiguous* blocks change
static inline void
__compute_upd_mac_mult_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  uint32_t nb_blocks = ((content_len-1) >> 4) + 1;
  memset(content + content_len, 0, nb_blocks * 16 - content_len);
  EverCrypt_AEAD_state_s* aead_state = upd_mac_state->aead_state;
  uint8_t ctr_block[BLOCK_LEN] = { 0U };
  uint8_t scratch[BLOCK_LEN] = { 0U };
  uint8_t *length;
  uint128_t tmp;

  my_memcpy(ctr_block, iv, IV_LEN);
  tmp = load128_be(ctr_block) + 1;
  store128_le(ctr_block, tmp);

  length = upd_mac_state->length_table + BLOCK_LEN * content_len;

  for (uint32_t i = 0; i < nb_changed_blocks; ++i) {
    uint32_t change_block_idx = first_change_block_idx + i;

    uint32_t htable_idx = nb_blocks - change_block_idx - 1;
    uint8_t* prev_block = prev_blocks + BLOCK_LEN * i;

    double_ghash_register(
      prev_block,
      content + change_block_idx * BLOCK_LEN,
      upd_mac_state->h_table + BLOCK_LEN * htable_idx,
      upd_mac_state->h_table,
      content_len
    );

    // ghash = prev_block;
    tmp = load128_le(prev_block) ^ load128_le(prev_ghash) ^ load128_le(length);
    store128_le(prev_ghash, tmp);
  }
  
  // compute AES(IV') ^ ghash
  gctr128_bytes(
    prev_ghash,
    (uint64_t)16U,
    tag,
    scratch,
    aead_state->ek,
    ctr_block,
    1U
  );
}

// FIXME(sadok): the following function should not be in this library
uint8_t
get_log_bit(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t log
)
{
  uint8_t scratch[BLOCK_LEN] = { 0U };
  uint8_t input[BLOCK_LEN] = { 0U };
  uint8_t result[BLOCK_LEN] = { 0U };

  input[0] = log & 0x1;

  EverCrypt_AEAD_state_s* aead_state = upd_mac_state->aead_state;

  gctr128_bytes(
    input,
    (uint64_t)16U,
    result,
    scratch,
    aead_state->ek,
    iv,
    1U
  );

  return result[0] & 0x1;
}

void
compute_upd_mac_mult_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_contig_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks, // point to the beginning of the first block
    first_change_block_idx,
    nb_changed_blocks,
    prev_ghash,
    tag
  );
}

void
compute_upd_mac_2_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_contig_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks, // point to the beginning of the first block
    first_change_block_idx,
    2,
    prev_ghash,
    tag
  );
}

void
compute_upd_mac_3_contig_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks, // point to the beginning of the first block
  uint32_t first_change_block_idx,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_contig_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks, // point to the beginning of the first block
    first_change_block_idx,
    3,
    prev_ghash,
    tag
  );
}

// use this function when multiple arbitrarily located blocks change
static inline void
__compute_upd_mac_mult_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks,
  uint32_t* change_block_idxes,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  uint32_t nb_blocks = ((content_len-1) >> 4) + 1;
  memset(content + content_len, 0, nb_blocks * 16 - content_len);
  EverCrypt_AEAD_state_s* aead_state = upd_mac_state->aead_state;
  uint8_t ctr_block[BLOCK_LEN] = { 0U };
  uint8_t scratch[BLOCK_LEN] = { 0U };
  uint8_t *length;
  uint128_t tmp;

  my_memcpy(ctr_block, iv, IV_LEN);
  tmp = load128_be(ctr_block) + 1;
  store128_le(ctr_block, tmp);

  length = upd_mac_state->length_table + BLOCK_LEN * content_len;

  for (uint32_t i = 0; i < nb_changed_blocks; ++i) {
    uint32_t change_block_idx = change_block_idxes[i];

    uint32_t htable_idx = nb_blocks - change_block_idx - 1;
    uint8_t* prev_block = prev_blocks + BLOCK_LEN * i;

    double_ghash_register(
      prev_block,
      content + change_block_idx * BLOCK_LEN,
      upd_mac_state->h_table + BLOCK_LEN * htable_idx,
      upd_mac_state->h_table,
      content_len
    );

    // ghash = prev_block;
    tmp = load128_le(prev_block) ^ load128_le(prev_ghash) ^ load128_le(length);
    store128_le(prev_ghash, tmp);
  }
  
  // compute AES(IV') ^ ghash
  gctr128_bytes(
    prev_ghash,
    (uint64_t)16U,
    tag,
    scratch,
    aead_state->ek,
    ctr_block,
    1U
  );
}

void
compute_upd_mac_mult_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks,
  uint32_t* change_block_idxes,
  uint32_t nb_changed_blocks,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks,
    change_block_idxes,
    nb_changed_blocks,
    prev_ghash,
    tag
  );
}

void
compute_upd_mac_2_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks,
  uint32_t* change_block_idxes,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks,
    change_block_idxes,
    2,
    prev_ghash,
    tag
  );
}

void
compute_upd_mac_3_blks(
  upd_mac_state_s* upd_mac_state,
  uint8_t* iv,
  uint8_t *content,
  uint32_t content_len,
  uint8_t* prev_blocks,
  uint32_t* change_block_idxes,
  uint8_t* prev_ghash,
  uint8_t* tag
)
{
  __compute_upd_mac_mult_blks(
    upd_mac_state,
    iv,
    content,
    content_len,
    prev_blocks,
    change_block_idxes,
    3,
    prev_ghash,
    tag
  );
}
