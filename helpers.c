#include <stdlib.h>
#include <stdio.h>

#include <EverCrypt_AEAD.h>

#include "inc_mac.h"
#include "helpers.h"

void print_hex_vector(const uint8_t* vector, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        printf("%02hhx ", vector[i]);
    }
    printf("\n");
}

int compare_tags(const uint8_t tag1[TAG_LEN], const uint8_t tag2[TAG_LEN],
                 bool verbose) {
    int ret = memcmp((char*) tag1, (char*) tag2, TAG_LEN);
    if (verbose) {
        printf("tag 1: ");
        print_hex_vector(tag1, TAG_LEN);

        printf("tag 2: ");
        print_hex_vector(tag2, TAG_LEN);
        if (ret) {
            printf("Tags differ\n");
        } else {
            printf("Tags match\n");
        }
    }
    
    return ret;
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

void get_ref_values(uint8_t* key, uint8_t* iv, uint8_t* message)
{
    if (key) {
        memcpy(key, ref_key, sizeof ref_key);
    }
    if (iv) {
        memcpy(iv, ref_iv, sizeof ref_iv);
    }
    if (message) {
        memcpy(message, ref_message, sizeof ref_message);
    }
}
