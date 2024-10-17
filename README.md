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



## RSA Encryption and Decryption Tool

This repository contains a command-line tool rsa_assign_1 implemented in C, which performs RSA key generation, encryption, decryption, and performance analysis using the GMP (GNU Multiple Precision Arithmetic Library).

### Features

Key Generation: Generate RSA public and private key pairs of specified lengths (1024, 2048, or 4096 bits).
Encryption: Encrypt plaintext files using RSA public keys.
Decryption: Decrypt ciphertext files using RSA private keys.
Performance Analysis: Compare the performance of RSA encryption and decryption with different key lengths in terms of computational time and memory usage.

### Requirements

GMP Library: The tool uses the GMP library for handling large integers required in RSA cryptography.


### Usage

The tool accepts various command-line options to perform different operations:


Usage: ``` rsa_assign_1 [options] ```

Options:
```
 -i path   Path to the input file
 -o path   Path to the output file
 -k path   Path to the key file
 -g length Generate RSA key-pair with given key length
 -d        Decrypt input and store results to output
 -e        Encrypt input and store results to output
 -a        Perform performance analysis
 -h        This help message
```

### Key Generation

Generate RSA key pairs of a specified length.
```
./rsa_assign_1 -g <key_length>
```

### Encryption

Encrypt a plaintext file using a public key.
```
./rsa_assign_1 -i <plaintext_file> -o <ciphertext_file> -k <public_key_file> -e
```

### Decryption

Decrypt a ciphertext file using a private key.
```
./rsa_assign_1 -i <ciphertext_file> -o <decrypted_file> -k <private_key_file> -d
```

### Performance Analysis

Perform performance analysis of RSA encryption and decryption with key lengths of 1024, 2048, and 4096 bits.

```
./rsa_assign_1 -a
```
### How it works

**Select Two Large Primes**: Randomly generate two distinct large prime numbers, p and q, each approximately half the desired key length.
Compute Modulus (n): Multiply the primes to get n:
```
n = p * q
```
This n is used as the modulus for both the public and private keys.


**Calculate Totient (λ(n))**: Compute Euler's totient function:
```
λ(n) = (p - 1) * (q - 1)
```

**Choose Public Exponent (e)**: Select a small odd integer e that is co-prime with λ(n) (our choice was 65537 since it is commonly used).

**Compute Private Exponent (d)**: Find d, the modular inverse of e modulo λ(n):
```
d ≡ e⁻¹ mod λ(n)
```

**Generate Key Pairs**:
-Public Key: (n, e)
-Private Key: (n, d)

### Encryption

Prepare the Plaintext: Convert the plaintext message into an integer m such that 0 ≤ m < n.
Encrypt: Compute the ciphertext c using the public key:
```
    c = m^e mod n
```

Output: The ciphertext c is the encrypted message.

### Decryption

Receive the Ciphertext: Obtain the ciphertext c.
Decrypt: Use the private key to compute the original message m:
```
m = c^d mod n
```


