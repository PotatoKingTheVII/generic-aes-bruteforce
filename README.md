## Overview

More generic sister project of https://github.com/PotatoKingTheVII/aesencryption-net-Bruteforce allowing wordlist attacks on different AES setups.

**Currently supports:**
 1. CBC/ECB Chaining modes
 2. User input IV or copying derived key as IV
 3. Optional PKCS7 validation
 4. 2 'KDF' modes, padding/duplicating key

**Plan to add:**
 1. PBKDF2 KDF
 2. MD5/SHA KDF
 3. Printing of best key/plaintext mid bruteforce

**Speed:**
Prioritised robustness/?generic-ness? above speed, so expect 1 million / second on 5 threads of a 3770k for reference.



## Usage

```
aesbrute.exe -w wordlist -t thread_count -m aes_mode -c ciphertext

-w : wordlist filename
-t : threadcount to use
-m : AES mode (1 = 128, 2 = 192, 3 = 256)
-c : ciphertext with correct padding
-d : digest mode (1 = pad with optional byte by -o, 2 = duplicate password). Default 1
-o : padding byte to use with -d 1 (0-255). Default 0
-v : Chaining mode, 0 = CBC, 1 = ECB. Default of 0 to match site
-p : Verify plaintext with PKCS7 padding. 0 = disabled 1 = enabled. Default is 1
-i : Specify what IV to use in CBC mode. Default is site's IV. Pass 'c' to copy key as the IV
-h : Show this help
```


## Building
Tested compilation under VS2019 c++14 both dynamically and statically linked to OpenSSL with vcpkg.
