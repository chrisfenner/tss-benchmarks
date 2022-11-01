# tss-benchmarks

Compare the speed of TPM operations across different TPM stacks

## Results

### Apple MacBook Air M2, 24GB RAM

#### Go

| Test Name                   | Iteration Count | Time Per Iteration |
| --------------------------- | --------------- | ------------------ |
| seal_unseal                 | 10000           | 243.68µs           |
| pcr_extend                  | 10000           | 61.583µs           |
| rsa_2048_create_sign_verify | 1000            | 22.137259ms        |
| ecc_p256_create_sign_verify | 10000           | 1.657945ms         |

## Tests

All versions of the tests expect a local TPM simulator running on the normal TCP
ports (2321/2322). They will Startup the TPM if needed.

### seal_unseal

1. Create a primary sealed data object with auth value "password" and contents
   "secrets"
1. Unseal the object with its password
1. Flush the object

### pcr_extend

1. Extend the data "measurement" into every PCR bank's PCR 0 using `PCR_Event`.

### rsa_2048_create_sign_verify

1. Fetch 4 bytes of randomness using `GetRandom`
1. Create a primary 2048-bit RSA-PSS signing key with the randomness in the
   `Unique` field of the template
1. Sign a 32-byte all-zero digest
1. Validate the signature
1. Flush the key

### ecc_p256_create_sign_verify

1. Fetch 4 bytes of randomness using `GetRandom`
1. Create a primary P256 ECDSA signing key with the randomness in the `Unique`
   field of the template
1. Sign a 32-byte all-zero digest
1. Validate the signature
1. Flush the key
