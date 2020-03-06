
#include <math.h>

#include "inc_mac.h"
#include "helpers.h"
#include "nss.h"

#define H_TABLE_SIZE 100

#define NB_ITERS (1L<<16)
#define NB_MEASUREMENTS 256

const uint16_t message_lens[] = {64, 112, 128, 256, 512, 1024};

double profile_mac(uint16_t extended_message_len)
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

    // printf("regular mac: %fns\n", ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9);

    free(extended_message);
    free_inc_mac(inc_mac_state);

    return ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9; // ns
}

double profile_nss_mac(uint16_t extended_message_len)
{
    uint8_t key[KEY_LEN];
    uint8_t iv[IV_LEN];
    uint8_t message[MESSAGE_LEN];
    uint8_t tag[TAG_LEN];
    clock_t t1, t2;
    uint8_t* extended_message;
    gcm_context_s* gctx;

    get_ref_values(key, iv, message);
    
    if (init_nss(&gctx, key, iv)) {
        fprintf(stderr, "Error initializing.");
        exit(1);
    }

    extended_message = get_extended_message(extended_message_len);
    
    t1 = clock();
    for (uint64_t i = 0; i < NB_ITERS; ++i) {
        mac_nss(gctx, extended_message, extended_message_len, tag, iv);
    }
    t2 = clock();

    // printf("regular nss mac: %fns\n", ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9);

    free(extended_message);
    free_nss(gctx);

    return ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9; // ns
}

double profile_upd_mac(uint32_t change_byte, uint16_t extended_message_len)
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

    // printf("updatable mac: %fns\n", ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9);

    free(extended_message);
    free_inc_mac(inc_mac_state);

    return ((double) (t2-t1)) / CLOCKS_PER_SEC / NB_ITERS * 1e9; // ns
}

void print_mean_std(double* data)
{
    double sum = 0;
    for (uint16_t i = 0; i < NB_MEASUREMENTS; ++i) {
        sum += data[i];
    }
    double mean = sum / NB_MEASUREMENTS;

    double std = 0;
    for (uint16_t i = 0; i < NB_MEASUREMENTS; ++i) {
        double diff = (data[i] - mean);
        std += diff * diff;
    }
    std = sqrt(std / NB_MEASUREMENTS);

    printf("%f +/- %f ns\n", mean, std);
}

int main()
{
    double nss_mac_measurements[sizeof(message_lens)][NB_MEASUREMENTS];
    double mac_measurements[sizeof(message_lens)][NB_MEASUREMENTS];
    double upd_mac_measurements[sizeof(message_lens)][NB_MEASUREMENTS];
    uint16_t nb_message_lens = sizeof(message_lens)/sizeof(message_lens[0]);

    for (uint16_t i = 0; i < NB_MEASUREMENTS; ++i) {
        printf("%i/%i\n", i+1, NB_MEASUREMENTS);
        for (uint16_t j = 0; j < nb_message_lens; ++j) {
            nss_mac_measurements[j][i] = profile_nss_mac(message_lens[j]);
            mac_measurements[j][i] = profile_mac(message_lens[j]);
            upd_mac_measurements[j][i] = profile_upd_mac(1, message_lens[j]);
        }
    }

    for (uint16_t i = 0; i < nb_message_lens; ++i) {
        printf("message len: %i\n", message_lens[i]);
        printf("NSS GMAC: ");
        print_mean_std(nss_mac_measurements[i]);

        printf("HACL* GMAC: ");
        print_mean_std(mac_measurements[i]);

        printf("Updatable GMAC: ");
        print_mean_std(upd_mac_measurements[i]);
        printf("\n");
    }

    return 0;
}
