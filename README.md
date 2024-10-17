# Systems_Security_ECDH_RSA
Implementations of the Elliptic Curve Diffie-Hellman key exchange and the RSA cryptography methods.

## Elliptic Curve Diffie-Hellman (ECDH) Key Exchange Tool

This repository contains a C program that implements the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol using the Curve25519 elliptic curve provided by the libsodium library. The tool allows two parties, Alice and Bob, to securely compute a shared secret over an insecure channel.

### Requirements

libsodium library: Ensure that you have the libsodium library installed on your system.
```
sudo apt-get install libsodium-dev
```

### Usage

Run the program with the required and optional command-line arguments:

```
./ecdh_assign_1 -o <output_file> [-a <alice_private_key>] [-b <bob_private_key>] [-h]
```

### Command-Line Options
```
-o path : Path to the output file (required).
-a number : Alice's private key (optional).
-b number : Bob's private key (optional).
-h : Display the help message.
```

### How It Works

Agreement on Elliptic Curve Parameters: Alice and Bob agree to use the Curve25519 elliptic curve.

Key Generation:

Alice:
Generates a private key (a).
Computes her public key **A = a * G**, where G is the base point.
        
Bob:
Generates a private key (b).
Computes his public key **B = b * G**.

Shared Secret Calculation:

Alice computes **S_A = a * B**.

Bob computes **S_B = b * A**.

Both shared secrets are the same: **S_A = S_B = (a * b) * G**.

### Notes

If private keys are provided via the -a or -b options, they are used directly.
If not provided, the tool generates random private keys using libsodium's secure random number generator.



## RSA Encryption and Decryption Tool in C

This repository contains a command-line tool rsa_assign_1 implemented in C, which performs RSA key generation, encryption, decryption, and performance analysis using the GMP (GNU Multiple Precision Arithmetic Library).

### Features

Key Generation: Generate RSA public and private key pairs of specified lengths (1024, 2048, or 4096 bits).
Encryption: Encrypt plaintext files using RSA public keys.
Decryption: Decrypt ciphertext files using RSA private keys.
Performance Analysis: Compare the performance of RSA encryption and decryption with different key lengths in terms of computational time and memory usage.

### Requirements

GMP Library: The tool uses the GMP library for handling large integers required in RSA cryptography.
C Compiler: GCC or any C compiler that supports linking with the GMP library.

### Compilation

Compile the program using the following command:

bash

gcc -o rsa_assign_1 rsa_assign_1.c -lgmp

Usage

The tool accepts various command-line options to perform different operations:


Usage: rsa_assign_1 [options]

Options:
 -i path   Path to the input file
 -o path   Path to the output file
 -k path   Path to the key file
 -g length Generate RSA key-pair with given key length
 -d        Decrypt input and store results to output
 -e        Encrypt input and store results to output
 -a        Perform performance analysis
 -h        This help message

### Key Generation

Generate RSA key pairs of a specified length.

bash

./rsa_assign_1 -g <key_length>

Example:

bash

    ./rsa_assign_1 -g 2048

    This command generates a 2048-bit RSA key pair and saves them as public_2048.key and private_2048.key.

### Encryption

Encrypt a plaintext file using a public key.

bash

./rsa_assign_1 -i <plaintext_file> -o <ciphertext_file> -k <public_key_file> -e

Example:

bash

    ./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public_2048.key -e

### Decryption

Decrypt a ciphertext file using a private key.

bash

./rsa_assign_1 -i <ciphertext_file> -o <decrypted_file> -k <private_key_file> -d

Example:

bash

    ./rsa_assign_1 -i ciphertext.txt -o decrypted.txt -k private_2048.key -d

### Performance Analysis

Perform performance analysis of RSA encryption and decryption with key lengths of 1024, 2048, and 4096 bits.

bash

./rsa_assign_1 -a

    Output: Results are saved to performance.txt.

Help

Display the help message.

bash

./rsa_assign_1 -h
