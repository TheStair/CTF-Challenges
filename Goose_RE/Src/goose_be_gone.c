//Compiled with GCC Default Options

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

// Uses Arithmetic to Dynamically create XOR key
char *superdupersecret() {
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

//XOR's the input string against a key
void Honk(const char *input, const char *key, char *encoded) {
    size_t input_len = strlen(input);
    size_t key_len = strlen(key);
    for (size_t i = 0; i < input_len; i++) {
        encoded[i] = input[i] ^ key[i % key_len];
    }
    encoded[input_len] = '\0';
}

//For encoding: Allocates 3 bytes for each original character and converts to a Hexadecimal String Representation
char *to_hex_string_space(const char *bin, size_t len) {
    size_t hex_len = len * 3;
    char *hex_str = malloc(hex_len);
    if (!hex_str) return NULL;
    hex_str[0] = '\0';
    for (size_t i = 0; i < len; i++) {
         char temp[4];
         if (i == len - 1)
             sprintf(temp, "%02x", (unsigned char)bin[i]);
         else
             sprintf(temp, "%02x ", (unsigned char)bin[i]);
         strcat(hex_str, temp);
    }
    return hex_str;
}

//Pieces together the first flag and compares it to the provided input
int SpecialSauce(const char *input) {
    const char *secret1 = "_g33se!";
    const char *secret2 = "I_H8";
    const char *secret3 = "_dum";
    const char *secret4 = "_stup1d";

    size_t totalLength = strlen(secret1) + strlen(secret2) + strlen(secret3) + strlen(secret4) + 1;
    char *combined = malloc(totalLength);
    if (!combined) return -1;

    strcpy(combined, secret2);
    strcat(combined, secret4);
    strcat(combined, secret3);
    strcat(combined, secret1);

    int cmp = strcmp(input, combined);
    free(combined);
    return cmp;
}

//Converts the ASCII Hex representation back to binary for XOR decoding
unsigned char *from_hex_string_space(const char *hex_str, size_t *out_len) {
    size_t count = 0;
    for (const char *p = hex_str; *p; p++) {
        if (!isspace((unsigned char)*p))
            count++;
    }
    if (count % 2 != 0) {
        return NULL;
    }
    size_t byte_len = count / 2;
    unsigned char *bytes = malloc(byte_len);
    if (!bytes) return NULL;

    for (size_t i = 0, j = 0; i < byte_len; i++) {
        while (isspace((unsigned char)hex_str[j])) j++;
        char hex_byte[3] = { hex_str[j], hex_str[j+1], '\0' };
        bytes[i] = (unsigned char)strtol(hex_byte, NULL, 16);
        j += 2;
    }
    if (out_len) {
        *out_len = byte_len;
    }
    return bytes;
}

//This function kinda just manages the whole second Challenge
// It prompts for the second password, encodes it, checks against the pre-defined password, then decodes the message if it's correct
void CheckCheck(void) {

    //Prompts for User input
    char input2[256];
    printf("Please enter a SECOND super secret password: ");
    if (fgets(input2, sizeof(input2), stdin)) {
        input2[strcspn(input2, "\n")] = '\0';
    } else {
        printf("Error reading MFA Code.\n");
        return;
    }
    
    //gets XOR Key
    char *secret = superdupersecret();
    if (!secret) {
         printf("Error generating secret.\n");
         return;
    }
    
    // Encodes user Input using XOR Key with malloc fail check
    size_t len = strlen(input2);
    char *encoded = malloc(len + 1);
    if (!encoded) {
         printf("Memory allocation failed for encoded input.\n");
         free(secret);
         return;
    }
    Honk(input2, secret, encoded);
    

    //Converts the encoded message to a string so I can use strcmp
    char *hex_encoded = to_hex_string_space(encoded, len);
    if (!hex_encoded) {
         printf("Memory allocation failed for hex conversion.\n");
         free(secret);
         free(encoded);
         return;
    }

    //Defines hardcoded password, XOR Encoded
    const char *encoded_password = "09 30 27 3a 35 08 06 78 0d 1e 29 23 67 1e 2e 20 3c 0a 25 79 60 33 65 6a 73 78";
    
    //Pre Encoded Secret Message (contains flag)
    const char *encoded_msg = "17 3a 37 69 38 32 25 39 72 38 66 2b 35 28 26 3b 6e 27 37 24 32 3b 2d 25 35 79 27 23 30 61 3c 27 2b 75 25 3b 3f 22 2a 2f 72 3b 23 2a 3d 2f 3b 6f 3a 3a 62 3a 38 36 2f 2e 72 53 66 14 3b 34 68 3c 2b 30 62 28 70 3f 31 2c 37 79 24 21 3d 2c 38 6f 3c 3c 31 20 3e 30 64 24 27 2d 66 22 32 61 3c 27 2b 75 32 26 3e 33 64 41 72 2d 2e 28 74 26 2d 2a 3d 30 62 28 3c 3b 64 2d 3e 3c 23 6d 3d 2f 68 29 2b 34 30 68 70 5d 64 3f 3a 3c 66 3d 35 33 23 6f 27 26 62 2f 22 32 21 6b 33 3e 27 24 3a 60 68 45 6e 1d 27 3b 35 77 2d 38 72 20 29 38 26 61 2e 23 2f 32 78 69 03 22 34 2e 20 06 01 22 3b 32 2d 10 0f 21 36 28 33 3c 1b 09 3e 30 2b 3d";
    
    // Compare's encoded user input against preset string
    if (strcmp(hex_encoded, encoded_password) == 0) {
         printf("MFA correct! Access granted.\n");
        
         //Decodes secret message if correct
         size_t bin_len;
         unsigned char *bin_encoded_msg = from_hex_string_space(encoded_msg, &bin_len);
         if (!bin_encoded_msg) {
             printf("Failed to convert hex string to binary.\n");
             free(secret);
             free(encoded);
             free(hex_encoded);
             return;
         }

         char *decoded_msg = malloc(bin_len + 1);
         if (!decoded_msg) {
             printf("Memory allocation failed for decoded message.\n");
             free(secret);
             free(encoded);
             free(hex_encoded);
             free(bin_encoded_msg);
             return;
         }

         size_t secret_len = strlen(secret);
         for (size_t i = 0; i < bin_len; i++) {
             decoded_msg[i] = bin_encoded_msg[i] ^ secret[i % secret_len];
         }
         decoded_msg[bin_len] = '\0';
         sleep(3);
         printf("%s\n", decoded_msg);
         free(bin_encoded_msg);
         free(decoded_msg);
    } else {
         printf("MFA incorrect! Access denied.\n");
    }
    
    free(secret);
    free(encoded);
    free(hex_encoded);
}

// Mostly holds print statements, but also mostly handles part 1
int main(void){
    char input1[256];

    printf("If the geese are running rampant, this device is the key,\n"
           "but first you'll have to provide the password for me.\n");
    printf("Please Enter the Password: ");
    if (fgets(input1, sizeof(input1), stdin)) {
        input1[strcspn(input1, "\n")] = '\0';
    }

    if (SpecialSauce(input1) == 0) {
        printf("Success!\n\n");
        printf("Wait Wait Wait, hold one a Minute...\n");
        sleep(1);
        printf("How do I really know you aren't a GOOSE?\n");
        sleep(1);
        printf("I will need another piece of information.\n");
        sleep(1);
        CheckCheck();
    }
    else {
        printf("Incorrect Password, Goodbye!\n");
        return 1;
    }
    return 0;
}
