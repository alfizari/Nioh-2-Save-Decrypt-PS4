# Nioh-2-Save-Decrypt-PS4
decrypted and encrypted nioh 2 ps4 saves

//////////////////////////////////////////////////
Custome AES CTR, uses custom S-Box. hardcoded Key and nonce/counter.

pure python would take 30 seconds to encrypt/decrypt.

checksum can be disabled by sitting certien flags to zero at offsets (not included in the script :
# Disable integrity checks
        data[0x7B882+0x10] = 0
        data[0x7B884+0x10] = 0
        data[0x7B7E4+0x10] = 0
        data[0xECF4A+0x10] = 0

Custom AES from: https://github.com/pawREP/Nioh-Savedata-Decryption-Tool
