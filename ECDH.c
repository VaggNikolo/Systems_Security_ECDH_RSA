#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>

/*Converts binary to hexadecimal string*/
void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

int main(int argc, char *argv[]) {
    unsigned char alice_private[crypto_scalarmult_SCALARBYTES];
    unsigned char alice_public[crypto_scalarmult_BYTES];
    unsigned char bob_private[crypto_scalarmult_SCALARBYTES];
    unsigned char bob_public[crypto_scalarmult_BYTES];
    unsigned char shared_secret_alice[crypto_scalarmult_BYTES];
    unsigned char shared_secret_bob[crypto_scalarmult_BYTES];
    char *output_path = NULL;
    char *a_private_key_str = NULL;
    char *b_private_key_str = NULL;
    int opt;

    /*CLI Args*/
    while ((opt = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            case 'a':
                a_private_key_str = optarg;
                break;
            case 'b':
                b_private_key_str = optarg;
                break;
            case 'h':
            default:
                printf("Usage: %s -o path [-a private_key_alice] [-b private_key_bob]\n", argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (!output_path) {
        fprintf(stderr, "Output file path is required.\n");
        exit(EXIT_FAILURE);
    }

    /*Libsodium init*/
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium.\n");
        return -1;
    }

    /*  Alice's private key generation
    In the case that it is provided use it
    Else generate it randomly   */
    if (a_private_key_str) {
        sodium_hex2bin(alice_private, sizeof(alice_private), a_private_key_str, strlen(a_private_key_str), NULL, NULL, NULL);
    } else {
        randombytes_buf(alice_private, sizeof(alice_private));
    }

    /*Computes Alice's public key*/
    crypto_scalarmult_base(alice_public, alice_private);

    /*  Bob's private key generation
    In the case that it is provided use it
    Else generate it randomly   */
    if (b_private_key_str) {
        sodium_hex2bin(bob_private, sizeof(bob_private), b_private_key_str, strlen(b_private_key_str), NULL, NULL, NULL);
    } else {
        randombytes_buf(bob_private, sizeof(bob_private));
    }

    /*Computes Bob's public key*/
    crypto_scalarmult_base(bob_public, bob_private);

    /*Computes shared secret from Alice's side*/
    if (crypto_scalarmult(shared_secret_alice, alice_private, bob_public) != 0) {
        fprintf(stderr, "Error computing shared secret on Alice's side.\n");
        return -1;
    }

    /*Computes shared secret from Bob's side*/
    if (crypto_scalarmult(shared_secret_bob, bob_private, alice_public) != 0) {
        fprintf(stderr, "Error computing shared secret on Bob's side.\n");
        return -1;
    }

    /*Check if shared secrets match*/
    if (memcmp(shared_secret_alice, shared_secret_bob, crypto_scalarmult_BYTES) != 0) {
        fprintf(stderr, "Shared secrets do not match!\n");
        return -1;
    }

    /*Convert shared keys and secrets to hex*/
    char alice_public_hex[crypto_scalarmult_BYTES * 2 + 1];
    char bob_public_hex[crypto_scalarmult_BYTES * 2 + 1];
    char shared_secret_hex[crypto_scalarmult_BYTES * 2 + 1];

    bin_to_hex(alice_public, crypto_scalarmult_BYTES, alice_public_hex);
    bin_to_hex(bob_public, crypto_scalarmult_BYTES, bob_public_hex);
    bin_to_hex(shared_secret_alice, crypto_scalarmult_BYTES, shared_secret_hex);

    /*Output to file*/
    FILE *fout = fopen(output_path, "w");
    if (!fout) {
        perror("Failed to open output file");
        return -1;
    }

    fprintf(fout, "Alice's Public Key:\n%s\n", alice_public_hex);
    fprintf(fout, "Bob's Public Key:\n%s\n", bob_public_hex);
    fprintf(fout, "Shared Secret (Alice):\n%s\n", shared_secret_hex);
    fprintf(fout, "Shared Secret (Bob):\n%s\n", shared_secret_hex);
    fprintf(fout, "Shared secrets match!\n");

    fclose(fout);

    printf("ECDH key exchange complete. Output written to %s.\n", output_path);

    return 0;
}
