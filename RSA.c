#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>

void generateRSAKeyPair(int key_length);
void encryptFile(const char *input_path, const char *output_path, const char *key_path, size_t *mem_usage);
void decryptFile(const char *input_path, const char *output_path, const char *key_path, size_t *mem_usage);
void performanceAnalysis(const char *performance_file);
int is_prime(mpz_t n, int reps);
size_t get_mpz_memory_usage(mpz_t var); // Function to calculate memory usage of mpz_t variables

int main(int argc, char *argv[]) {
    int opt;
    int key_length = 0;
    int generate = 0, encrypt = 0, decrypt = 0, analyze = 0;
    char *input_path = NULL, *output_path = NULL, *key_path = NULL;
    char *performance_file = NULL;

    while ((opt = getopt(argc, argv, "i:o:k:g:deha:")) != -1) {
        switch (opt) {
            case 'i':
                input_path = strdup(optarg);
                break;
            case 'o':
                output_path = strdup(optarg);
                break;
            case 'k':
                key_path = strdup(optarg);
                break;
            case 'g':
                generate = 1;
                key_length = atoi(optarg);
                break;
            case 'd':
                decrypt = 1;
                break;
            case 'e':
                encrypt = 1;
                break;
            case 'a':
                analyze = 1;
                performance_file = strdup(optarg);
                break;
            case 'h':
            default:
                printf("Usage: %s [options]\n", argv[0]);
                printf("Options:\n");
                printf(" -i path   Path to the input file\n");
                printf(" -o path   Path to the output file\n");
                printf(" -k path   Path to the key file\n");
                printf(" -g length Generate RSA key-pair with given key length\n");
                printf(" -d        Decrypt input and store results to output\n");
                printf(" -e        Encrypt input and store results to output\n");
                printf(" -a path   Perform performance analysis and output to file\n");
                printf(" -h        This help message\n");
                exit(0);
        }
    }

    if (generate) {
        generateRSAKeyPair(key_length);
    } else if (encrypt) {
        if (!input_path || !output_path || !key_path) {
            fprintf(stderr, "Error: -i, -o, and -k options are required for encryption\n");
            exit(1);
        }
        encryptFile(input_path, output_path, key_path, NULL);
    } else if (decrypt) {
        if (!input_path || !output_path || !key_path) {
            fprintf(stderr, "Error: -i, -o, and -k options are required for decryption\n");
            exit(1);
        }
        decryptFile(input_path, output_path, key_path, NULL);
    } else if (analyze) {
        if (!performance_file) {
            fprintf(stderr, "Error: -a option requires an output file path\n");
            exit(1);
        }
        performanceAnalysis(performance_file);
    } else {
        fprintf(stderr, "Error: No operation specified. Use -h for help.\n");
        exit(1);
    }

    // Free allocated memory
    free(input_path);
    free(output_path);
    free(key_path);
    free(performance_file);

    return 0;
}

void generateRSAKeyPair(int key_length) {
    mpz_t p, q, n, lambda_n, e, d, gcd_result;
    gmp_randstate_t state;
    unsigned long int seed;
    int half_key_length = key_length / 2;

    mpz_inits(p, q, n, lambda_n, e, d, gcd_result, NULL);
    gmp_randinit_mt(state);
    seed = (unsigned long int) time(NULL);
    gmp_randseed_ui(state, seed);

    // Generate two distinct large prime numbers p and q
    do {
        mpz_urandomb(p, state, half_key_length);
        mpz_nextprime(p, p);
    } while (!is_prime(p, 25));

    do {
        mpz_urandomb(q, state, half_key_length);
        mpz_nextprime(q, q);
    } while (!is_prime(q, 25) || mpz_cmp(p, q) == 0);

    // Compute n = p * q
    mpz_mul(n, p, q);

    // Compute lambda(n) = (p - 1) * (q - 1)
    mpz_t p_minus_1, q_minus_1;
    mpz_inits(p_minus_1, q_minus_1, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(lambda_n, p_minus_1, q_minus_1);

    // Choose e
    mpz_set_ui(e, 65537); // Common choice for e
    mpz_gcd(gcd_result, e, lambda_n);
    while (mpz_cmp_ui(gcd_result, 1) != 0) {
        mpz_add_ui(e, e, 2);
        mpz_gcd(gcd_result, e, lambda_n);
    }

    // Compute d, the modular inverse of e mod lambda(n)
    if (mpz_invert(d, e, lambda_n) == 0) {
        fprintf(stderr, "Error computing modular inverse.\n");
        exit(1);
    }

    // Save public key (n, d)
    char public_key_filename[256];
    sprintf(public_key_filename, "public_%d.key", key_length);
    FILE *pub_file = fopen(public_key_filename, "w");
    if (!pub_file) {
        perror("Error opening public key file");
        exit(1);
    }
    mpz_out_str(pub_file, 16, n); // Save n
    fprintf(pub_file, "\n");
    mpz_out_str(pub_file, 16, d); // Save d
    fclose(pub_file);

    // Save private key (n, e)
    char private_key_filename[256];
    sprintf(private_key_filename, "private_%d.key", key_length);
    FILE *priv_file = fopen(private_key_filename, "w");
    if (!priv_file) {
        perror("Error opening private key file");
        exit(1);
    }
    mpz_out_str(priv_file, 16, n); // Save n
    fprintf(priv_file, "\n");
    mpz_out_str(priv_file, 16, e); // Save e
    fclose(priv_file);

    printf("Keys generated and saved to %s and %s\n", public_key_filename, private_key_filename);

    // Clear variables
    mpz_clears(p, q, n, lambda_n, e, d, gcd_result, p_minus_1, q_minus_1, NULL);
    gmp_randclear(state);
}

void encryptFile(const char *input_path, const char *output_path, const char *key_path, size_t *mem_usage) {
    mpz_t n, d, plaintext, ciphertext;
    mpz_inits(n, d, plaintext, ciphertext, NULL);

    // Read public key (n, d)
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        perror("Error opening key file");
        exit(1);
    }
    mpz_inp_str(n, key_file, 16);
    mpz_inp_str(d, key_file, 16);
    fclose(key_file);

    // Read plaintext from input file
    FILE *in_file = fopen(input_path, "rb"); // Open in binary mode
    if (!in_file) {
        perror("Error opening input file");
        exit(1);
    }
    fseek(in_file, 0, SEEK_END);
    long filesize = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    if (filesize == 0) {
        fprintf(stderr, "Error: Input file is empty.\n");
        fclose(in_file);
        exit(1);
    }
    unsigned char *buffer = malloc(filesize);
    if (!buffer) {
        perror("Error allocating memory for plaintext");
        fclose(in_file);
        exit(1);
    }
    fread(buffer, 1, filesize, in_file);
    fclose(in_file);

    // Convert buffer to mpz_t plaintext
    mpz_import(plaintext, filesize, 1, 1, 0, 0, buffer);
    free(buffer);

    // Check if plaintext >= n
    if (mpz_cmp(plaintext, n) >= 0) {
        fprintf(stderr, "Error: Plaintext too large. Must be less than modulus n.\n");
        exit(1);
    }

    // Encrypt: ciphertext = plaintext^d mod n
    mpz_powm(ciphertext, plaintext, d, n);

    // Write ciphertext to output file
    FILE *out_file = fopen(output_path, "w");
    if (!out_file) {
        perror("Error opening output file");
        exit(1);
    }
    mpz_out_str(out_file, 16, ciphertext);
    fclose(out_file);

    if (mem_usage != NULL) {
        *mem_usage = get_mpz_memory_usage(n) + get_mpz_memory_usage(d) +
                     get_mpz_memory_usage(plaintext) + get_mpz_memory_usage(ciphertext);
    }

    printf("Encryption complete. Ciphertext saved to %s\n", output_path);

    mpz_clears(n, d, plaintext, ciphertext, NULL);
}

void decryptFile(const char *input_path, const char *output_path, const char *key_path, size_t *mem_usage) {
    mpz_t n, e, plaintext, ciphertext;
    mpz_inits(n, e, plaintext, ciphertext, NULL);

    // Read private key (n, e)
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        perror("Error opening key file");
        exit(1);
    }
    mpz_inp_str(n, key_file, 16);
    mpz_inp_str(e, key_file, 16);
    fclose(key_file);

    // Read ciphertext from input file
    FILE *in_file = fopen(input_path, "r");
    if (!in_file) {
        perror("Error opening input file");
        exit(1);
    }
    if (mpz_inp_str(ciphertext, in_file, 16) == 0) {
        fprintf(stderr, "Error reading ciphertext\n");
        fclose(in_file);
        exit(1);
    }
    fclose(in_file);

    // Decrypt: plaintext = ciphertext^e mod n
    mpz_powm(plaintext, ciphertext, e, n);

    // Convert plaintext mpz_t to buffer
    size_t count;
    unsigned char *buffer = mpz_export(NULL, &count, 1, 1, 0, 0, plaintext);

    // Write plaintext to output file
    FILE *out_file = fopen(output_path, "wb"); // Open in binary mode
    if (!out_file) {
        perror("Error opening output file");
        exit(1);
    }
    fwrite(buffer, 1, count, out_file);
    fclose(out_file);
    free(buffer);

    if (mem_usage != NULL) {
        *mem_usage = get_mpz_memory_usage(n) + get_mpz_memory_usage(e) +
                     get_mpz_memory_usage(plaintext) + get_mpz_memory_usage(ciphertext);
    }

    printf("Decryption complete. Plaintext saved to %s\n", output_path);

    mpz_clears(n, e, plaintext, ciphertext, NULL);
}

size_t get_mpz_memory_usage(mpz_t var) {
    size_t limbs = mpz_size(var);
    size_t limb_size = sizeof(mp_limb_t);
    return limbs * limb_size;
}

void performanceAnalysis(const char *performance_file) {
    int key_lengths[] = {1024, 2048, 4096};
    char *plaintext_file = "plaintext.txt";
    FILE *perf_file = fopen(performance_file, "w");
    if (!perf_file) {
        perror("Error opening performance file");
        exit(1);
    }

    for (int i = 0; i < 3; i++) {
        int key_length = key_lengths[i];
        struct timeval start, end;
        double enc_time, dec_time;
        size_t enc_mem_usage = 0, dec_mem_usage = 0;

        // Generate keys
        generateRSAKeyPair(key_length);

        // Encrypt
        gettimeofday(&start, NULL);
        char public_key_filename[256];
        sprintf(public_key_filename, "public_%d.key", key_length);
        encryptFile(plaintext_file, "ciphertext.txt", public_key_filename, &enc_mem_usage);
        gettimeofday(&end, NULL);
        enc_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;

        // Decrypt
        gettimeofday(&start, NULL);
        char private_key_filename[256];
        sprintf(private_key_filename, "private_%d.key", key_length);
        decryptFile("ciphertext.txt", "decrypted.txt", private_key_filename, &dec_mem_usage);
        gettimeofday(&end, NULL);
        dec_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;

        // Write results
        fprintf(perf_file, "Key Length: %d bits\n", key_length);
        fprintf(perf_file, "Encryption Time: %.4fs\n", enc_time);
        fprintf(perf_file, "Decryption Time: %.4fs\n", dec_time);
        fprintf(perf_file, "Memory Usage (Encryption): %zu Bytes\n", enc_mem_usage);
        fprintf(perf_file, "Memory Usage (Decryption): %zu Bytes\n\n", dec_mem_usage);
    }

    fclose(perf_file);
    printf("Performance analysis complete. Results saved to %s\n", performance_file);
}

int is_prime(mpz_t n, int reps) {
    return mpz_probab_prime_p(n, reps);
}
