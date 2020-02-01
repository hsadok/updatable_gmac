
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "inc_mac.h"
#include "helpers.h"

int test_first_mac(bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    inc_mac_state_s* inc_mac_state;

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }
    compute_first_mac(inc_mac_state, iv, message, MESSAGE_LEN, tag);
    
    free_inc_mac(inc_mac_state);
    
    int ret = compare_tags(tag, expected_tag, verbose);
    if (ret) {
        printf("compute_first_mac failed\n");
    } else {
        printf("compute_first_mac works\n");
    }
    return ret;
}

int test_gctr128(bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t my_expected_tag[TAG_LEN];
    inc_mac_state_s* inc_mac_state;
    uint8_t ctr_block[16U] = { 0U };
    uint8_t inout_b[16U] = { 0U };
    uint128_t tmp;

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    compute_first_mac(inc_mac_state, iv, message, MESSAGE_LEN, my_expected_tag);

    memcpy(ctr_block, iv, IV_LEN);
    tmp = load128_be(ctr_block) + 1;
    store128_le(ctr_block, tmp);

    if (verbose) {
        printf("previous ghash: ");
        print_hex_vector(inc_mac_state->prev_ghash, sizeof inc_mac_state->prev_ghash);

        printf("  expected_tag: ");
        print_hex_vector(expected_tag, sizeof expected_tag);
    }

    gctr128_bytes(
        inc_mac_state->prev_ghash,
        (uint64_t)16U,
        tag,
        inout_b,
        inc_mac_state->aead_state->ek,
        ctr_block,
        1U
    );

    if (verbose) {
        printf("           tag: ");
        print_hex_vector(tag, sizeof tag);
    }

    int ret = memcmp((char*) tag, (char*) expected_tag, TAG_LEN);
    ret = ret || memcmp((char*) tag, (char*) my_expected_tag, TAG_LEN);
    if (ret) {
        printf("gctr128 failed\n");
    } else {
        printf("gctr128 works\n");
    }
    return ret;
}

int compare_ghash_register(uint8_t* result, uint8_t* h_table_entry, bool verbose)
{
    int ret = memcmp((char*) result, (char*) h_table_entry, GHASH_LEN);

    if (verbose) {
        printf("       result: ");
        print_hex_vector(result, GHASH_LEN);

        printf("h_table_entry: ");
        print_hex_vector(h_table_entry, GHASH_LEN);
    }
    
    if (ret) {
        printf("GHASH verification failed\n");
    }
    return ret;
}

void print_htable(uint8_t* h_table) {
    printf("h_table:\n");
    for (int i = 0; i < 8; ++i) {
        printf("  [%i]: ", i);
        print_hex_vector(h_table + GHASH_LEN * i, GHASH_LEN);
    }
}

int test_ghash_register(bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    inc_mac_state_s* inc_mac_state;
    int ret;
    uint8_t test[GHASH_LEN] = {0};

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }
    uint8_t *hkeys_b = inc_mac_state->aead_state->ek + (uint32_t)176U;

    if (verbose) {
        print_htable(hkeys_b);
    }

    ghash_register(test, hkeys_b, hkeys_b);
    if (verbose) {
        printf("h_table[0]: h\n");
    }
    ret = compare_ghash_register(test, hkeys_b + GHASH_LEN, verbose);
    if (ret) {
        free_inc_mac(inc_mac_state);
        return ret;
    }

    memset(test, 0, GHASH_LEN);
    ghash_register(test, hkeys_b + GHASH_LEN, hkeys_b);

    if (verbose) {
        printf("h_table[1]: h^2\n");
    }
    ret = compare_ghash_register(test, hkeys_b + GHASH_LEN * 3, verbose);
    if (ret) {
        free_inc_mac(inc_mac_state);
        return ret;
    }

    memset(test, 0, GHASH_LEN);
    ghash_register(test, hkeys_b + GHASH_LEN * 3, hkeys_b);

    if (verbose) {
        printf("h_table[3]: h^3\n");
    }
    ret = compare_ghash_register(test, hkeys_b + GHASH_LEN * 4, verbose);
    if (ret) {
        free_inc_mac(inc_mac_state);
        return ret;
    }

    memset(test, 0, GHASH_LEN);
    ghash_register(test, hkeys_b + GHASH_LEN * 4, hkeys_b);

    if (verbose) {
        printf("h_table[4]: h^4\n");
    }
    ret = compare_ghash_register(test, hkeys_b + GHASH_LEN * 6, verbose);
    if (ret) {
        free_inc_mac(inc_mac_state);
        return ret;
    }

    memset(test, 0, GHASH_LEN);
    ghash_register(test, hkeys_b + GHASH_LEN * 6, hkeys_b);

    if (verbose) {
        printf("h_table[6]: h^5\n");
    }
    ret = compare_ghash_register(test, hkeys_b + GHASH_LEN * 7, verbose);
    if (ret) {
        free_inc_mac(inc_mac_state);
        return ret;
    }

    printf("ghash_register works\n");
    
    free_inc_mac(inc_mac_state);
    return 0;
}

int test_xor_ghash(int32_t change_byte, bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t tag_org[TAG_LEN];
    uint8_t tag_mod[TAG_LEN];
    uint8_t tag_xor[TAG_LEN];
    uint8_t ghash_org[GHASH_LEN];
    uint8_t ghash_mod[GHASH_LEN];
    uint8_t ghash_xor[GHASH_LEN];
    uint8_t aes_org[TAG_LEN];
    uint8_t aes_mod[TAG_LEN];
    uint8_t aes_xor[TAG_LEN];
    uint8_t length[BLOCK_LEN] = { 0U };
    uint8_t mod_message[MESSAGE_LEN] = { 0U };
    uint8_t xor_message[MESSAGE_LEN] = { 0U };
    uint8_t scratch[MESSAGE_LEN] = { 0U };
    inc_mac_state_s* inc_mac_state;
    uint128_t tmp;

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    memcpy(mod_message, message, MESSAGE_LEN);

    if (change_byte >= 0) {
        mod_message[change_byte] = message[change_byte]+1;
    }

    for (uint16_t i = 0; i < MESSAGE_LEN; ++i) {
        xor_message[i] = message[i] ^ mod_message[i];
    }

    compute_first_mac(inc_mac_state, iv, message, MESSAGE_LEN, tag_org);
    memcpy(ghash_org, inc_mac_state->prev_ghash, GHASH_LEN);
    tmp = load128_le(tag_org) ^ load128_le(ghash_org);
    store128_le(aes_org, tmp);

    if (verbose) {
        printf("ORIGINAL\n");
        printf("  message: ");
        print_hex_vector(message, MESSAGE_LEN);
        printf("                  tag: ");
        print_hex_vector(tag_org, TAG_LEN);
        printf("                ghash: ");
        print_hex_vector(ghash_org, GHASH_LEN);
        printf("                  aes: ");
        print_hex_vector(aes_org, GHASH_LEN);
    }

    compute_first_mac(inc_mac_state, iv, mod_message, MESSAGE_LEN, tag_mod);
    memcpy(ghash_mod, inc_mac_state->prev_ghash, GHASH_LEN);
    tmp = load128_le(tag_mod) ^ load128_le(ghash_mod);
    store128_le(aes_mod, tmp);

    if (verbose) {
        printf("MOD\n");
        printf("  message: ");
        print_hex_vector(mod_message, MESSAGE_LEN);
        printf("                  tag: ");
        print_hex_vector(tag_mod, TAG_LEN);
        printf("                ghash: ");
        print_hex_vector(ghash_mod, GHASH_LEN);
        printf("                  aes: ");
        print_hex_vector(aes_mod, GHASH_LEN);
        
        tmp = load128_le(ghash_org) ^ load128_le(ghash_mod);
        store128_le(scratch, tmp);
        printf("  ghash_org^ghash_mod: ");
        print_hex_vector(scratch, GHASH_LEN);
    }

    compute_first_mac(inc_mac_state, iv, xor_message, MESSAGE_LEN, tag_xor);
    memcpy(ghash_xor, inc_mac_state->prev_ghash, GHASH_LEN);
    tmp = load128_le(tag_xor) ^ load128_le(ghash_xor);
    store128_le(aes_xor, tmp);

    if (verbose) {
        printf("XOR\n");
        printf("  message: ");
        print_hex_vector(xor_message, MESSAGE_LEN);
        printf("                  tag: ");
        print_hex_vector(tag_xor, TAG_LEN);
        printf("                ghash: ");
        print_hex_vector(ghash_xor, GHASH_LEN);
        printf("                  aes: ");
        print_hex_vector(aes_xor, GHASH_LEN);

        tmp = load128_le(ghash_xor) ^ load128_le(ghash_org);
        store128_le(scratch, tmp);
        printf("  ghash_xor^ghash_org: ");
        print_hex_vector(scratch, GHASH_LEN);

        tmp = load128_le(ghash_xor) ^ load128_le(ghash_mod);
        store128_le(scratch, tmp);
        printf("  ghash_xor^ghash_mod: ");
        print_hex_vector(scratch, GHASH_LEN);
    }

    *(((uint64_t*) length) + 1) = MESSAGE_LEN * 8;

    memset(scratch, 0, GHASH_LEN);
    ghash_register(scratch, length, inc_mac_state->h_table);
    if (verbose) {
        printf("\nscratch: ");
        print_hex_vector(scratch, GHASH_LEN);
    }
    tmp = load128_be(scratch) // the result must be converted to big endian
          ^ load128_le(ghash_xor) ^ load128_le(ghash_mod);
    store128_le(scratch, tmp);

    if (verbose) {
        printf("ghash_org?: ");
        print_hex_vector(scratch, TAG_LEN);
    }

    tmp = load128_le(scratch) ^ load128_le(aes_mod);
    store128_le(tag, tmp);

    int ret = compare_tags(tag, expected_tag, verbose);

    free_inc_mac(inc_mac_state);
    
    if (ret) {
        printf("test_xor_ghash failed\n");
    } else {
        printf("test_xor_ghash works\n");
    }
    return ret;
}

int test_inc_mac(uint32_t change_byte, bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t prev_block[BLOCK_LEN];
    inc_mac_state_s* inc_mac_state;
    int32_t change_block_idx = change_byte >> 4; // 128-bit blocks

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    ++(iv[IV_LEN - 1]);
    ++(message[change_byte]);

    compute_first_mac(inc_mac_state, iv, message, MESSAGE_LEN, tag);

    if (verbose) {
        printf("first tag: ");
        print_hex_vector(tag, TAG_LEN);
        printf("change_block_idx: %u\n", change_block_idx);    
    }

    memcpy(prev_block, message + change_block_idx * BLOCK_LEN, BLOCK_LEN);

    if (verbose) {
        printf("prev block: ");
        print_hex_vector(prev_block, BLOCK_LEN);
    }

    --(iv[IV_LEN - 1]);
    --(message[change_byte]);
    
    compute_inc_mac(
        inc_mac_state,
        iv,
        message,
        MESSAGE_LEN,
        prev_block,
        change_block_idx,
        tag
    );

    free_inc_mac(inc_mac_state);
    
    int ret = compare_tags(tag, expected_tag, verbose);
    if (ret) {
        printf("inc mac failed\n");
    } else {
        printf("inc mac works\n");
    }
    return ret;
}

int test_large_inc_mac(uint32_t change_byte, uint16_t message_len, bool verbose)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t my_expected_tag[TAG_LEN];
    uint8_t prev_block[BLOCK_LEN];
    inc_mac_state_s* inc_mac_state;
    int32_t change_block_idx = change_byte >> 4; // 128-bit blocks
    uint8_t* extended_message;

    get_ref_values(key, iv, NULL);

    extended_message = get_extended_message(message_len);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    ++(iv[IV_LEN - 1]);
    ++(extended_message[change_byte]);

    compute_first_mac(inc_mac_state, iv, extended_message, message_len, tag);

    if (verbose) {
        printf("first tag: ");
        print_hex_vector(tag, TAG_LEN);
        printf("change_block_idx: %u\n", change_block_idx);    
    }

    memcpy(prev_block, extended_message + change_block_idx * BLOCK_LEN, BLOCK_LEN);

    if (verbose) {
        printf("prev block: ");
        print_hex_vector(prev_block, BLOCK_LEN);
    }

    --(iv[IV_LEN - 1]);
    --(extended_message[change_byte]);
    
    compute_inc_mac(
        inc_mac_state,
        iv,
        extended_message,
        message_len,
        prev_block,
        change_block_idx,
        tag
    );

    compute_first_mac(
        inc_mac_state,
        iv,
        extended_message,
        message_len,
        my_expected_tag
    );

    free_inc_mac(inc_mac_state);
    free(extended_message);
    
    int ret = compare_tags(tag, my_expected_tag, verbose);
    if (ret) {
        printf("large inc mac failed\n");
    } else {
        printf("large inc mac works\n");
    }
    return ret;
}

int main()
{
    assert(test_first_mac(false) == 0);
    assert(test_gctr128(false) == 0);
    assert(test_ghash_register(false) == 0);
    assert(test_xor_ghash(-1, false) == 0);
    assert(test_xor_ghash(0, false) == 0);
    assert(test_xor_ghash(15, false) == 0);
    assert(test_xor_ghash(16, false) == 0);
    assert(test_xor_ghash(17, false) == 0);
    assert(test_inc_mac(0, false) == 0);
    assert(test_inc_mac(15, false) == 0);
    assert(test_inc_mac(16, false) == 0);
    assert(test_inc_mac(17, false) == 0);
    assert(test_large_inc_mac(17, 1500, false) == 0);
    
    return 0;
}
