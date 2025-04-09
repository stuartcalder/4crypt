# 4crypt
![Alt text](/share/title.png "4crypt")
![Alt text](/share/logo.png  "Dragon")

Symmetric file encryption tool, targeting 512 bits of security with memory-hard password hashing.


.------.
|4crypt|
'------'
-h, --help                  Print help output.
-e, --encrypt=<filepath>    Encrypt the file at the filepath.
-d, --decrypt=<filepath>    Decrypt the file at the filepath.
-D, --describe=<filepath>   Describe the header of encrypted file at the filepath.
-o, --output=<filepath>     Specify an output filepath.
-E, --entropy               Provide addition entropy to the RNG from stdin.
-H, --high-mem=<mem[K|M|G]> Provide an upper memory bound for key derivation.
-L, --low-mem=<mem[K|M|G]>  Provide a lower memory bound for key derivation.
-M, --use-mem=<mem[K|M|G]>  Set the lower and upper memory bounds to the same value.
-I, --iterations=<num>      Set the number of times to iterate the KDF.
-T, --threads=<num>         Set the degree of parallelism for the KDF.
-B, --batch-size=<num>      Set the number of KDF threads to execute concurrently.
-1, --enter-password-once   Disable password-reentry for correctness verification during encryption.
-P, --use-phi               Enable the Phi function for each KDF thread.
--pad-as-if=<size>          Pad the output ciphertext as if it were an unpadded encrypted file of this size.
--pad-by=<size>             Pad the output ciphertext by this many bytes, rounded up such that the produced
                              ciphertext is evenly divisible by 64.
--pad-to=<size>             Pad the output ciphertext to the target size, rounded up such that the produced
                              ciphertext is evenly divisible by 64.
WARNING: The phi function hardens the key-derivation function against
parallel adversaries, greatly increasing the work necessary to brute-force
your password, but introduces the potential for cache-timing attacks.
Do NOT use this feature unless you understand the security implications!
## Buildtime Dependencies
### (Required on all supported systems)
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
