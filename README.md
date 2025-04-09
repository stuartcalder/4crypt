![Alt text](/share/title.png "4crypt")
![Alt text](/share/logo.png  "Dragon")

Symmetric file encryption tool, targeting 512 bits of security with memory-hard password hashing.

This software aims to provide strong symmetric cryptographic security for protecting important data.
Both CLI and GUI interfaces are provided.

![Alt text](../screenshots/gui.png)
![Alt text](../screenshots/cli.png)

## Buildtime Dependencies
-   [SSC](https://github.com/stuartcalder/SSC) header and library files.
-   [tsc_c](https://github.com/stuartcalder/tsc_c) header and library files.
### (Required on OpenBSD, FreeBSD, MacOS, and GNU/Linux)
-   __ncurses__ header and library files.
### (Required on Microsoft Windows only)
-   __Windows Vista/Server 2008__ or later.
-   __Visual Studio 2019__ development suite or later.
## Building 4crypt
1. Build and install [SSC](https://github.com/stuartcalder/SSC.git).
2. Build and install [tsc_c](https://github.com/stuartcalder/tsc_c.git).
3. cmake -S . -B ${BUILD_DIR}
4. cd ${BUILD_DIR}
5. make -j${NPROC}
## Implementation Detail
The three most significant algorithms implemented and utilized in this project include:
1. The [Threefish512](https://en.wikipedia.org/wiki/Threefish) block cipher.
2. The [Skein512](https://en.wikipedia.org/wiki/Skein_(hash_function)) cryptographic hash function.
3. A customized implementation of the CATENA password scrambling framework.

User supplied passwords are scrambled using CATENA and then hashed into two 512 bit keys; the first
is used as the secret key for Threefish512 in Counter Mode for confidentiality; the second is used
as the secret key for Skein512's native Message Authentication Code, which is appended to the end
of encrypted files for authentication and integrity verification.

The beginning of every 4crypt-encrypted file is a header, consisting of:
1. The magic bytes [0xE2, 0x2A, 0x1E, 0x9B] to uniquely identify 4crypt-encrypted files.
2. 4 bytes encoding:
    1. The Lower Memory Bound of the Key Derivation Function, CATENA.
    2. The Upper Memory Bound of the Key Derivation Function, CATENA.
    3. The Iteration Count    of the Key Derivation Function, CATENA.
    4. A boolean encoding whether to enable "Phi" and Sequential Memory Hardness (Discussed later).
3. 64 bit, little endian encoded unsigned integer describing the total size of the file.
4. 128 pseudorandom bits utilized as a Threefish512 tweak for Threefish in Counter Mode.
5. 256 pseudorandom bits utilized as a cryptographic salt for CATENA.
6. 256 pseudorandom bits utilized as an initialization vector for Threefish in Counter Mode.
7. 64 bit, little endian encoded unsigned integer describing the thread count for CATENA.
8. 64 reserved bits, currently always all zero.
9. 64 bit, Threefish512-CTR enciphered, little endian encoded unsigned integer describing the total number of padding bytes.
10. 64 Threefish512-CTR enciphered reserved bits. Currently the plaintext is always all zero.

All 4crypt-encrypted files are evenly divisible into 64 byte blocks; i.e. the payload of the file plus
the metadata of the file header, the MAC appenended to the end, and the
padding bytes always evenly divides by 64 bytes.

