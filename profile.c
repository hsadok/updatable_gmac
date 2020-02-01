
#include "inc_mac.h"

#define MESSAGE_LEN 20
#define HTABLE_SIZE 100

#define NB_ITERS (1L<<25)

#define MIN(a,b) (((a)<(b))?(a):(b))

static uint8_t key[KEY_LEN] = {
    0x2f, 0xb4, 0x5e, 0x5b, 0x8f, 0x99, 0x3a, 0x2b,
    0xfe, 0xbc, 0x4b, 0x15, 0xb5, 0x33, 0xe0, 0xb4
};
static uint8_t iv[IV_LEN] = {
    0x5b, 0x05, 0x75, 0x5f, 0x98, 0x4d, 0x2b, 0x90,
    0xf9, 0x4b, 0x80, 0x27
};
static uint8_t ref_message[MESSAGE_LEN] = {
    0xe8, 0x54, 0x91, 0xb2, 0x20, 0x2c, 0xaf, 0x1d,
    0x7d, 0xce, 0x03, 0xb9, 0x7e, 0x09, 0x33, 0x1c,
    0x32, 0x47, 0x39, 0x41
};

const uint16_t message_lens[] = {64, 128, 256, 512, 1024};

static void print_hex_vector(const uint8_t* vector, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx ", vector[i]);
    }
    printf("\n");
}

uint8_t* get_extended_message(uint16_t extended_message_len)
{
    uint8_t* extended_message;

    extended_message = malloc(extended_message_len);
    if (extended_message == NULL) {
        exit(2);
    }
    for (uint16_t i = 0; i < extended_message_len; i+= MESSAGE_LEN) {
        memcpy(
            extended_message + i,
            ref_message,
            MIN(MESSAGE_LEN, extended_message_len - i)
        );
    }

    return extended_message;
}

void profile_mac(uint16_t extended_message_len)
{
    uint8_t tag[TAG_LEN];
    inc_mac_state_s* inc_mac_state;
    clock_t t1, t2;
    uint8_t* extended_message;

    if (init_inc_mac(&inc_mac_state, key, HTABLE_SIZE)) {
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
    uint8_t tag[TAG_LEN];
    uint8_t prev_block[BLOCK_LEN];
    inc_mac_state_s* inc_mac_state;
    int32_t change_block_idx = change_byte >> 4; // 128-bit blocks
    clock_t t1, t2;
    uint8_t* extended_message;

    if (init_inc_mac(&inc_mac_state, key, HTABLE_SIZE)) {
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
