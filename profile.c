
#include "inc_mac.h"
#include "helpers.h"


#define H_TABLE_SIZE 100

#define NB_ITERS (1L<<25)


const uint16_t message_lens[] = {64, 128, 256, 512, 1024};

void profile_mac(uint16_t extended_message_len)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    inc_mac_state_s* inc_mac_state;
    clock_t t1, t2;
    uint8_t* extended_message;

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    extended_message = get_extended_message(extended_message_len);

    compute_first_mac(inc_mac_state, iv, extended_message, MESSAGE_LEN, tag);
    
    t1 = clock();
    for (uint64_t i = 0; i < NB_ITERS; ++i) {
        encrypt_aes128_gcm(
            inc_mac_state->aead_state,
            iv,
            IV_LEN,
            extended_message,
            extended_message_len,
            NULL, // no plain data
            0,    // no plain data
            NULL, // we don't care about the encrypted output
            tag
        );
    }
    t2 = clock();

    printf("regular mac: %fs\n", ((double) (t2-t1)) / CLOCKS_PER_SEC);

    free(extended_message);
    free_inc_mac(inc_mac_state);
}

void profile_inc_mac(uint32_t change_byte, uint16_t extended_message_len)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t prev_block[BLOCK_LEN];
    inc_mac_state_s* inc_mac_state;
    int32_t change_block_idx = change_byte >> 4; // 128-bit blocks
    clock_t t1, t2;
    uint8_t* extended_message;

    get_ref_values(key, iv, message);

    if (init_inc_mac(&inc_mac_state, key, H_TABLE_SIZE, LENGTH_TABLE_SIZE)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    extended_message = get_extended_message(extended_message_len);

    compute_first_mac(inc_mac_state, iv, extended_message, MESSAGE_LEN, tag);
    
    t1 = clock();
    for (uint64_t i = 0; i < NB_ITERS; ++i) {
        memcpy(prev_block, extended_message + change_block_idx * BLOCK_LEN, BLOCK_LEN);
        compute_inc_mac(
            inc_mac_state,
            iv,
            extended_message,
            MESSAGE_LEN,
            prev_block,
            change_block_idx,
            tag
        );
    }
    t2 = clock();

    printf("incremental mac: %fs\n", ((double) (t2-t1)) / CLOCKS_PER_SEC);

    free(extended_message);
    free_inc_mac(inc_mac_state);
}

int main()
{
    for (uint16_t i = 0; i < sizeof(message_lens)/sizeof(message_lens[0]); ++i) {
        printf("message len: %i\n", message_lens[i]);
        profile_mac(message_lens[i]);
        profile_inc_mac(1, message_lens[i]);
        printf("\n");
    }
    return 0;
}
