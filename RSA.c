#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

// Function to generate RSA key pair
void generateRSAKeyPair(int key_length) {
    mpz_t p, q, n, lambda_n, e, d;
    gmp_randstate_t state;
    unsigned long int seed = time(NULL);

    // Initialize GMP variables
    mpz_inits(p, q, n, lambda_n, e, d, NULL);
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);

    // Generate p and q (random primes of size key_length/2)
    int half_key_len = key_length / 2;
    mpz_urandomb(p, state, half_key_len);
    mpz_urandomb(q, state, half_key_len);
    mpz_nextprime(p, p);
    mpz_nextprime(q, q);

    // Compute n = p * q
    mpz_mul(n, p, q);

    // Compute lambda(n) = (p-1) * (q-1)
    mpz_t p1, q1;
    mpz_inits(p1, q1, NULL);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lambda_n, p1, q1);

    // Choose e = 65537 (common value for e)
    mpz_set_ui(e, 65537);

    // Compute d, the modular inverse of e mod lambda(n)
    if (mpz_invert(d, e, lambda_n) == 0) {
        printf("Modular inverse of e and lambda(n) does not exist!\n");
        return;
    }

    // Output public key (n, e) and private key (n, d)
    char pub_key_file[50], priv_key_file[50];
    sprintf(pub_key_file, "public_%d.key", key_length);
    sprintf(priv_key_file, "private_%d.key", key_length);
    
    FILE *pub_file = fopen(pub_key_file, "w");
    FILE *priv_file = fopen(priv_key_file, "w");
    gmp_fprintf(pub_file, "%Zx\n%Zx\n", n, e);  // Public key
    gmp_fprintf(priv_file, "%Zx\n%Zx\n", n, d); // Private key

    // Clean up
    fclose(pub_file);
    fclose(priv_file);
    mpz_clears(p, q, n, lambda_n, e, d, p1, q1, NULL);
    gmp_randclear(state);
}

void rsaEncrypt(const char *inputFile, const char *outputFile, const char *keyFile) {
    mpz_t plaintext, ciphertext, n, e;
    mpz_inits(plaintext, ciphertext, n, e, NULL);

    // Read public key (n, e)
    FILE *key = fopen(keyFile, "r");
    if (key == NULL) {
        printf("Error: Could not open key file %s\n", keyFile);
        exit(1);
    }
    gmp_fscanf(key, "%Zx\n%Zx\n", n, e);
    fclose(key);
    gmp_printf("Public key loaded. n = %Zx, e = %Zx\n", n, e);

    // Read plaintext from input file (as raw text)
    FILE *input = fopen(inputFile, "r");
    if (input == NULL) {
        printf("Error: Could not open input file %s\n", inputFile);
        exit(1);
    }

    // Read the entire file content as a string
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    rewind(input);
    char *file_content = malloc(file_size + 1);
    fread(file_content, 1, file_size, input);
    fclose(input);
    file_content[file_size] = '\0';

    // Convert the plaintext (file content) to a GMP integer (plaintext as raw text)
    mpz_import(plaintext, file_size, 1, sizeof(file_content[0]), 0, 0, file_content);
    free(file_content);

    gmp_printf("Plaintext loaded as integer: %Zx\n", plaintext);

    // Check if the plaintext is smaller than n
    if (mpz_cmp(plaintext, n) >= 0) {
        printf("Error: Plaintext is larger than n, which is not allowed in RSA.\n");
        mpz_clears(plaintext, ciphertext, n, e, NULL);
        exit(1);
    }

    // Compute ciphertext = (plaintext^e) % n
    mpz_powm(ciphertext, plaintext, e, n);
    gmp_printf("Ciphertext computed: %Zx\n", ciphertext);

    // Output ciphertext to output file
    FILE *output = fopen(outputFile, "w");
    if (output == NULL) {
        printf("Error: Could not open output file %s\n", outputFile);
        exit(1);
    }
    gmp_fprintf(output, "%Zx\n", ciphertext);
    fclose(output);

    mpz_clears(plaintext, ciphertext, n, e, NULL);
}



// Function to decrypt the data
void rsaDecrypt(const char *inputFile, const char *outputFile, const char *keyFile) {
    mpz_t plaintext, ciphertext, n, d;
    mpz_inits(plaintext, ciphertext, n, d, NULL);

    // Read private key (n, d)
    FILE *key = fopen(keyFile, "r");
    if (key == NULL) {
        printf("Error: Could not open key file %s\n", keyFile);
        exit(1);
    }
    gmp_fscanf(key, "%Zx\n%Zx\n", n, d);
    fclose(key);
    gmp_printf("Private key loaded. n = %Zx, d = %Zx\n", n, d);

    // Read ciphertext from input file
    FILE *input = fopen(inputFile, "r");
    if (input == NULL) {
        printf("Error: Could not open input file %s\n", inputFile);
        exit(1);
    }
    gmp_fscanf(input, "%Zx\n", ciphertext);
    fclose(input);
    gmp_printf("Ciphertext loaded: %Zx\n", ciphertext);

    // Compute plaintext = (ciphertext^d) % n
    mpz_powm(plaintext, ciphertext, d, n);
    gmp_printf("Plaintext computed: %Zx\n", plaintext);

    // Export plaintext to a readable format (back to raw text)
    size_t count;
    char *decrypted_text = (char *)mpz_export(NULL, &count, 1, 1, 0, 0, plaintext);

    // Output plaintext to output file as raw text
    FILE *output = fopen(outputFile, "w");
    if (output == NULL) {
        printf("Error: Could not open output file %s\n", outputFile);
        exit(1);
    }
    fwrite(decrypted_text, 1, count, output);
    fclose(output);

    free(decrypted_text);
    mpz_clears(plaintext, ciphertext, n, d, NULL);
}



// Function to measure performance
#include <sys/time.h>
#include <sys/resource.h>

void measurePerformance(const char *performanceFile) {
    struct timeval start, end;
    struct rusage usage;
    FILE *performance = fopen(performanceFile, "w");

    if (performance == NULL) {
        printf("Error: Could not open performance file %s\n", performanceFile);
        exit(1);
    }

    int key_lengths[] = {1024, 2048, 4096};
    for (int i = 0; i < 3; i++) {
        int key_length = key_lengths[i];
        printf("Measuring performance for key length: %d bits\n", key_length);

        // Measure time for key generation
        gettimeofday(&start, NULL);
        generateRSAKeyPair(key_length);
        gettimeofday(&end, NULL);
        long keygen_time = ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
        
        // Measure memory usage for key generation
        getrusage(RUSAGE_SELF, &usage);
        long memory_usage_keygen = usage.ru_maxrss;

        // Dummy encryption and decryption files
        char plaintext_file[20] = "plaintext.txt";
        char ciphertext_file[20] = "ciphertext.txt";
        char decrypted_file[20] = "decrypted.txt";
        char pub_key_file[50], priv_key_file[50];

        sprintf(pub_key_file, "public_%d.key", key_length);
        sprintf(priv_key_file, "private_%d.key", key_length);

        // Measure time for encryption
        gettimeofday(&start, NULL);
        rsaEncrypt(plaintext_file, ciphertext_file, pub_key_file);
        gettimeofday(&end, NULL);
        long encrypt_time = ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
        
        // Measure memory usage for encryption
        getrusage(RUSAGE_SELF, &usage);
        long memory_usage_encrypt = usage.ru_maxrss;

        // Measure time for decryption
        gettimeofday(&start, NULL);
        rsaDecrypt(ciphertext_file, decrypted_file, priv_key_file);
        gettimeofday(&end, NULL);
        long decrypt_time = ((end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);

        // Measure memory usage for decryption
        getrusage(RUSAGE_SELF, &usage);
        long memory_usage_decrypt = usage.ru_maxrss;

        // Write results to performance.txt
        fprintf(performance, "Key Length: %d bits\n", key_length);
        fprintf(performance, "Key Generation Time: %.3f seconds\n", keygen_time / 1000000.0);
        fprintf(performance, "Encryption Time: %.3f seconds\n", encrypt_time / 1000000.0);
        fprintf(performance, "Decryption Time: %.3f seconds\n", decrypt_time / 1000000.0);
        fprintf(performance, "Peak Memory Usage (Key Generation): %ld KB\n", memory_usage_keygen);
        fprintf(performance, "Peak Memory Usage (Encryption): %ld KB\n", memory_usage_encrypt);
        fprintf(performance, "Peak Memory Usage (Decryption): %ld KB\n", memory_usage_decrypt);
        fprintf(performance, "-------------------------------------------\n");
    }

    fclose(performance);
}


// Command-line parsing and main function
int main(int argc, char *argv[]) {
    int opt;
    int key_length = 0;
    char *input_file = NULL;
    char *output_file = NULL;
    char *key_file = NULL;
    char *performance_file = NULL;

    while ((opt = getopt(argc, argv, "i:o:k:g:deha:")) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'g':
                key_length = atoi(optarg);
                generateRSAKeyPair(key_length);
                break;
            case 'd':
                rsaDecrypt(input_file, output_file, key_file);
                break;
            case 'e':
                rsaEncrypt(input_file, output_file, key_file);
                break;
            case 'a':
                performance_file = optarg;
                measurePerformance(performance_file);
                break;
            case 'h':
            default:
                printf("Usage: ./rsa_assign_1 -g length\n"
                       "       ./rsa_assign_1 -i input.txt -o output.txt -k keyfile -e|-d\n"
                       "       ./rsa_assign_1 -a performance.txt\n");
                exit(EXIT_FAILURE);
        }
    }

    return 0;
}

