#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>

void generateRSAKeyPair(int key_length);
void encryptFile(const char *input_path, const char *output_path, const char *key_path);
void decryptFile(const char *input_path, const char *output_path, const char *key_path);
void performanceAnalysis();
int is_prime(mpz_t n, int reps);

int main(int argc, char *argv[]) {
    int opt;
    int key_length = 0;
    int generate = 0, encrypt = 0, decrypt = 0, analyze = 0;
    char *input_path = NULL, *output_path = NULL, *key_path = NULL;

    while ((opt = getopt(argc, argv, "i:o:k:g:deah")) != -1) {
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
                printf(" -a        Perform performance analysis\n");
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
        encryptFile(input_path, output_path, key_path);
    } else if (decrypt) {
        if (!input_path || !output_path || !key_path) {
            fprintf(stderr, "Error: -i, -o, and -k options are required for decryption\n");
            exit(1);
        }
        decryptFile(input_path, output_path, key_path);
    } else if (analyze) {
        performanceAnalysis();
    } else {
        fprintf(stderr, "Error: No operation specified. Use -h for help.\n");
        exit(1);
    }

    // Free allocated memory
    free(input_path);
    free(output_path);
    free(key_path);

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

void encryptFile(const char *input_path, const char *output_path, const char *key_path) {
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

    printf("Encryption complete. Ciphertext saved to %s\n", output_path);

    mpz_clears(n, d, plaintext, ciphertext, NULL);
}

void decryptFile(const char *input_path, const char *output_path, const char *key_path) {
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

    printf("Decryption complete. Plaintext saved to %s\n", output_path);

    mpz_clears(n, e, plaintext, ciphertext, NULL);
}

void performanceAnalysis() {
    int key_lengths[] = {1024, 2048, 4096};
    char *plaintext_file = "plaintext.txt";
    char *performance_file = "performance.txt";
    FILE *perf_file = fopen(performance_file, "w");
    if (!perf_file) {
        perror("Error opening performance file");
        exit(1);
    }

    for (int i = 0; i < 3; i++) {
        int key_length = key_lengths[i];
        struct timeval start, end;
        struct rusage usage_start, usage_end;
        double enc_time, dec_time;
        long enc_mem, dec_mem;

        // Generate keys
        generateRSAKeyPair(key_length);

        // Encrypt
        gettimeofday(&start, NULL);
        getrusage(RUSAGE_SELF, &usage_start);
        char public_key_filename[256];
        sprintf(public_key_filename, "public_%d.key", key_length);
        encryptFile(plaintext_file, "ciphertext.tmp", public_key_filename);
        gettimeofday(&end, NULL);
        getrusage(RUSAGE_SELF, &usage_end);
        enc_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        enc_mem = usage_end.ru_maxrss - usage_start.ru_maxrss;

        // Decrypt
        gettimeofday(&start, NULL);
        getrusage(RUSAGE_SELF, &usage_start);
        char private_key_filename[256];
        sprintf(private_key_filename, "private_%d.key", key_length);
        decryptFile("ciphertext.tmp", "decrypted.tmp", private_key_filename);
        gettimeofday(&end, NULL);
        getrusage(RUSAGE_SELF, &usage_end);
        dec_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        dec_mem = usage_end.ru_maxrss - usage_start.ru_maxrss;

        // Write results
        fprintf(perf_file, "Key Length: %d bits\n", key_length);
        fprintf(perf_file, "Encryption Time: %.4fs\n", enc_time);
        fprintf(perf_file, "Decryption Time: %.4fs\n", dec_time);
        fprintf(perf_file, "Peak Memory Usage (Encryption): %ld Bytes\n", enc_mem);
        fprintf(perf_file, "Peak Memory Usage (Decryption): %ld Bytes\n\n", dec_mem);
    }

    fclose(perf_file);
    printf("Performance analysis complete. Results saved to %s\n", performance_file);
}

int is_prime(mpz_t n, int reps) {
    return mpz_probab_prime_p(n, reps);
}
