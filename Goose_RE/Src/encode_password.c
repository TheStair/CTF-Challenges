#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *create_obfuscated_secret() {
    int len = 16;  
    char *secret = malloc(len + 1);  
    if (!secret) {
        return NULL;
    }
    for (int i = 0; i < len; i++) {
        secret[i] = (char)(((i * 7 + 13) % 26) + 'A');
    }
    secret[len] = '\0';
    return secret;
}


void xor_encode(const char *input, const char *key, char *encoded) {
    size_t input_len = strlen(input);
    size_t key_len = strlen(key);
    for (size_t i = 0; i < input_len; i++) {
        encoded[i] = input[i] ^ key[i % key_len];
    }
    encoded[input_len] = '\0';
}

int main(void) {
    char *secret = create_obfuscated_secret();
    if (!secret) {
        fprintf(stderr, "Error: could not generate secret.\n");
        return 1;
    }

    const char *correct_password = "Geese_B3_Gon3_for_g00d!!!!";

    size_t cp_len = strlen(correct_password);
    char *precomputed_encoded = malloc(cp_len + 1);
    if (!precomputed_encoded) {
        fprintf(stderr, "Memory allocation failed for precomputed password.\n");
        free(secret);
        return 1;
    }

    xor_encode(correct_password, secret, precomputed_encoded);

    printf("Dynamic secret: %s\n", secret);
    printf("Precomputed encoded password (hex): ");
    for (size_t i = 0; i < cp_len; i++) {
        printf("%02x ", (unsigned char)precomputed_encoded[i]);
    }
    printf("\n");

    const char *secret_message = "You hear a faint rumbling and the ground begins to shake \nYou see a huge blimp rising out of the pond \nthe geese all flee in fear! \nthe park is free again! \nHere is your flag: Super_Goose_Attack_Blimp";
    size_t msg_len = strlen(secret_message);
    char *encoded_msg = malloc(msg_len + 1);
    if (!encoded_msg) {
        fprintf(stderr, "Memory allocation failed for precomputed password.\n");
        free(secret);
        return 1;
    }
    printf("\n Encoded Message: ");
    xor_encode(secret_message, secret, encoded_msg);
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02x ", (unsigned char)encoded_msg[i]);
    }
   
    free(secret);
    free(precomputed_encoded);
    return 0;
}
