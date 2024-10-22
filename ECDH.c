#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>


int main(int argc, char *argv[]) {
    //Key Pair for Alice
    unsigned char alice_private_key[crypto_box_SECRETKEYBYTES];
    unsigned char alice_public_key[crypto_box_PUBLICKEYBYTES];
    //Key Pair for Bob
    unsigned char bob_private_key[crypto_box_SECRETKEYBYTES];
    unsigned char bob_public_key[crypto_box_PUBLICKEYBYTES];
    
    unsigned char alice_shared_secret[crypto_scalarmult_BYTES];
    unsigned char bob_shared_secret[crypto_scalarmult_BYTES];
    
    char *output_path = NULL;
    char *a_private_key_str = NULL;
    char *b_private_key_str = NULL;
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (opt) {
            // Path to Output File
            case 'o':
                output_path = optarg;
                break;
            // Alice's private key
            case 'a':
                a_private_key_str = optarg;
                break;
            // Bob's private key
            case 'b':
                b_private_key_str = optarg;
                break;
            // This Help Message
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

    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium.\n");
        return -1;
    }

    // Set Alice's private key
    if (a_private_key_str != NULL) {
        // Use provided private key for Alice and convert it into a byte sequence(decoding)
        sodium_hex2bin(alice_private_key, sizeof(alice_private_key), a_private_key_str, strlen(a_private_key_str), NULL, NULL, NULL);
    } else {
        // Generate random private key for Alice
        randombytes_buf(alice_private_key, sizeof(alice_private_key));
    }

    // Compute Alice's public key
    crypto_scalarmult_base(alice_public_key, alice_private_key);

    // Set Bob's private key
    if (b_private_key_str != NULL) {
        // Use provided private key for Bob
        sodium_hex2bin(bob_private_key, sizeof(bob_private_key), b_private_key_str, strlen(b_private_key_str), NULL, NULL, NULL);
    } else {
        // Generate random private key for Bob
        randombytes_buf(bob_private_key, sizeof(bob_private_key));
    }

    // Compute Bob's public key
    crypto_scalarmult_base(bob_public_key, bob_private_key);

    // Compute shared secret: Alice's side using alice's private key and bob's public key
    if (crypto_scalarmult(alice_shared_secret, alice_private_key, bob_public_key) != 0) {
        fprintf(stderr, "Error computing shared secret on Alice's side.\n");
        return -1;
    }

    // Compute shared secret: Bob's side using bob's private key and alice's private key
    if (crypto_scalarmult(bob_shared_secret, bob_private_key, alice_public_key) != 0) {
        fprintf(stderr, "Error computing shared secret on Bob's side.\n");
        return -1;
    }

    // Check if shared secrets match
    if (memcmp(alice_shared_secret, bob_shared_secret, crypto_scalarmult_BYTES) != 0) {
        fprintf(stderr, "Shared secrets do not match!\n");
        return -1;
    }
    
    char alice_public_key_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char bob_public_key_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char alice_shared_secret_hex[crypto_scalarmult_BYTES * 2 + 1]; 
    char bob_shared_secret_hex[crypto_scalarmult_BYTES * 2 + 1];

    // Convert keys and shared secrets to hexadecimal strings
    sodium_bin2hex(alice_public_key_hex, sizeof(alice_public_key_hex), alice_public_key, sizeof(alice_public_key));
    sodium_bin2hex(bob_public_key_hex, sizeof(bob_public_key_hex), bob_public_key, sizeof(bob_public_key));
    sodium_bin2hex(alice_shared_secret_hex, sizeof(alice_shared_secret_hex), alice_shared_secret, sizeof(alice_shared_secret));
    sodium_bin2hex(bob_shared_secret_hex, sizeof(bob_shared_secret_hex), bob_shared_secret, sizeof(bob_shared_secret));
    

    // Write the public keys of Alice and Bob and the shared secret to the specified path
    FILE *fout = fopen(output_path, "w");
    if (!fout) {
        perror("Failed to open output file");
        return -1;
    }
    fprintf(fout, "Alice's Public Key:\n%s\n", alice_public_key_hex);
    fprintf(fout, "Bob's Public Key:\n%s\n", bob_public_key_hex);
    fprintf(fout, "Shared Secret (Alice):\n%s\n", alice_shared_secret_hex);
    fprintf(fout, "Shared Secret (Bob):\n%s\n", bob_shared_secret_hex);
    fprintf(fout, "Shared secrets match!\n");
    fclose(fout);

    printf("ECDH key exchange complete. Output written to %s.\n", output_path);

    return 0;
}