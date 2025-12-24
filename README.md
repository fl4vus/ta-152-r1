# ta-152-r1
![alt text](https://raw.githubusercontent.com/fl4vus/ta-152-r1/main/mascot_ta152_r1.png)

## TA-152-R1 Cipher (Original Implementation)
TA-152-R1 is a improvement over my [TA-152-R0](https://github.com/fl4vus/ta-152-r0 "TA-152-R0") cipher, and implements IV for better key non-determinism.

TA-152-R1 passes a complete functional regression test suite _(test.sh)_, including determinism, IV-based non-determinism, key sensitivity, binary safety, and wrong-key robustness.
The project currently has **EXPERIMENTAL** stability, and is not suitable for production cryptography.

### Build Instructions
```
git clone https://github.com/fl4vus/ta-152-r1
cd ta-152-r1/
make
```

### Usage
```
./ta152 encrypt <input_file> <keyfile> -iv # Encryption w/ IV
./ta152 encrypt <input_file> <keyfile>     # Encryption w/o IV
./ta152 decrypt <input_file> <keyfile>     # Decryption
```

### Build
Language: ISO C11  
Compiler: GCC / Clang  
Platform: Linux / Unix  
Build system: Make  
Dependencies: libc / glibc

### Documentation
Specifications: [TA-152-R1-SPEC](https://github.com/fl4vus/ta-152-r1/tree/main/documentation/spec.pdf)


_AUTHOR: Riyan Dahiya_
