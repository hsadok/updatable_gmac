
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "inc_mac.h"

#define MESSAGE_LEN 20

#define CHANGE_BYTE 16 // byte in second 128-bit block

static uint8_t key[KEY_LEN] = {
    0x2f, 0xb4, 0x5e, 0x5b, 0x8f, 0x99, 0x3a, 0x2b,
    0xfe, 0xbc, 0x4b, 0x15, 0xb5, 0x33, 0xe0, 0xb4
};
static uint8_t iv[IV_LEN] = {
    0x5b, 0x05, 0x75, 0x5f, 0x98, 0x4d, 0x2b, 0x90,
    0xf9, 0x4b, 0x80, 0x27
};
static uint8_t message[MESSAGE_LEN] = {
    0xe8, 0x54, 0x91, 0xb2, 0x20, 0x2c, 0xaf, 0x1d,
    0x7d, 0xce, 0x03, 0xb9, 0x7e, 0x09, 0x33, 0x1c,
    0x32, 0x47, 0x39, 0x41
};
static uint8_t expected_tag[TAG_LEN] = {
    0xc7, 0x5b, 0x78, 0x32, 0xb2, 0xa2, 0xd9, 0xbd,
    0x82, 0x74, 0x12, 0xb6, 0xef, 0x57, 0x69, 0xdb
};

void print_hex_vector(uint8_t* vector, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx ", vector[i]);
    }
    printf("\n");
}

int compare_tags(uint8_t tag1[TAG_LEN], uint8_t tag2[TAG_LEN]) {
    int ret = strncmp((char*) tag1, (char*) tag2, TAG_LEN);
    if (ret) {
        printf("Tags differ\n");

        printf("tag 1: ");
        print_hex_vector(tag1, TAG_LEN);

        printf("tag 2: ");
        print_hex_vector(tag2, TAG_LEN);
    } else {
        printf("Tags match\n");
    }
    return ret;
}

int test_first_mac()
{
    uint8_t tag[TAG_LEN];
    inc_mac_state_s inc_mac_state;

    if (init_inc_mac(&inc_mac_state, key)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }
    compute_first_mac(&inc_mac_state, iv, message, MESSAGE_LEN, tag);
    
    free_inc_mac(&inc_mac_state);
    
    return compare_tags(tag, expected_tag);
}

int test_ghash_register()
{
    inc_mac_state_s inc_mac_state;
    uint8_t test1[16] = {0};
    // uint8_t test2[16] = {0};

    if (init_inc_mac(&inc_mac_state, key)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }
    uint8_t *hkeys_b = inc_mac_state.aead_state->ek + (uint32_t)176U;

    ghash_register(test1, hkeys_b, hkeys_b);

    int ret = strncmp((char*) test1, (char*) (hkeys_b + 16), 16);
    if (ret) {
        printf("GHASH verification failed\n");
        printf("test1: ");
        print_hex_vector(test1, 16);

        printf("hkeys_b: ");
        print_hex_vector(hkeys_b, 16);

        printf("hkeys_b + 16: ");
        print_hex_vector(hkeys_b + 16, 16);
    } else {
        printf("ghash_register works\n");
    }
    return ret;
    // ghash_register(test2, hkeys_b + 16, hkeys_b);
}

// int test_inc_mac()
// {
//     uint8_t tag[TAG_LEN];
//     inc_mac_state_s inc_mac_state;

//     if (init_inc_mac(&inc_mac_state, key)) {
//         fprintf(stderr, "Error initializing.");
//         exit(1);
//     }

//     ++(iv[IV_LEN - 1]);
//     ++(message[CHANGE_BYTE]);

//     compute_first_mac(&inc_mac_state, iv, message, MESSAGE_LEN, tag);
    
//     --(iv[IV_LEN - 1]);
//     --(message[CHANGE_BYTE]);
    
//     compute_inc_mac(&inc_mac_state, iv, message, MESSAGE_LEN, tag, CHANGE_BYTE);

//     free_inc_mac(&inc_mac_state);
    
//     return compare_tags(tag, expected_tag);
// }

int main()
{
    assert(test_first_mac() == 0);
    assert(test_ghash_register() == 0);
    // assert(test_inc_mac() == 0);
    
    return 0;
}
