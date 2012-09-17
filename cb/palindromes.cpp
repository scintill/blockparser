#include <stdio.h>

#include "callback.h"
#include "util.h"



enum  optionIndex { kUnknown };
static const option::Descriptor usageDescriptor[] =
{
    { kUnknown, 0, "", "", option::Arg::None, "\n\n        dump palindromic hashes and data\n" },
    { 0,        0,  0,  0,                 0,        0    }
};

class Palindromes : public Callback {
    virtual void startTX(const uint8_t *p, const uint8_t *hash) {
        checkPalindrome(hash, 256, "Transaction");
    }

    void move(
        const uint8_t *script,
        uint64_t      scriptSize,
        const uint8_t *txHash,
        int64_t        value,
        const uint8_t *downTXHash = 0
    )
    {
        uint8_t addrType[3];
        uint160_t pubKeyHash;
        int type = solveOutputScript(pubKeyHash.v, script, scriptSize, addrType);
        if(unlikely(type<0)) return;

        checkPalindrome(pubKeyHash.v, 160, "Pubkey hash");
    }

    virtual void endOutput(
        const uint8_t *p,
        uint64_t      value,
        const uint8_t *txHash,
        uint64_t      outputIndex,
        const uint8_t *outputScript,
        uint64_t      outputScriptSize
    )
    {
        move( outputScript, outputScriptSize, txHash, value);
    }

    virtual void edge(
        uint64_t      value,
        const uint8_t *upTXHash,
        uint64_t      outputIndex,
        const uint8_t *outputScript,
        uint64_t      outputScriptSize,
        const uint8_t *downTXHash,
        uint64_t      inputIndex,
        const uint8_t *inputScript,
        uint64_t      inputScriptSize
    )
    {
        move( outputScript, outputScriptSize, upTXHash, -(int64_t)value, downTXHash);
    }
    
    virtual void startBlock(const Block *b) {
        const uint8_t *p = b->data;

        sha256Twice(this->curBlockHash, p, 80);
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        LOAD(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, bTime, p);
        LOAD(uint32_t, nNonce, p);

        checkPalindrome(this->curBlockHash, 256, "Block hash");
        checkPalindrome(&blkMerkleRoot.v[0], 256, "Block merkle root");
        checkPalindrome((uint8_t*)&bTime, 32, "Block timestamp");
        checkDecimalPalindrome(bTime, "Block timestamp");
        checkPalindrome((uint8_t*)&nNonce, 32, "Block nonce");
        checkDecimalPalindrome(nNonce, "Block nonce");
    }

    virtual const char *name() const {
        return "palindromes";
    }

    virtual const option::Descriptor *usage() const {
        return usageDescriptor;
    }

    virtual bool needTXHash() { return true; }

    private:
    uint8_t curBlockHash[kSHA256ByteSize];

    void checkPalindrome(const uint8_t *data, int bits, const char *tag) {
        bool found = false;
        if (isBinaryPalindrome(data, bits)) {
            found = true;
            printf("%s 0x", tag);
            showHex(data, bits/8);
            printf(" is a binary palindrome");
        } else if (isHexPalindrome(data, bits)) {
            found = true;
            printf("%s 0x", tag);
            showHex(data, bits/8);
            printf(" is a hex palindrome");
        }

        if (found) {
            printf(" in block ");
            showHex(curBlockHash);
            printf("\n");
        }
    }

    void checkDecimalPalindrome(uint64_t data, const char *tag) {
        if (isDecimalPalindrome(data)) {
            printf("%s %ld is a decimal palindrome in block ", tag, data);
            showHex(curBlockHash);
            printf("\n");
        }
    }

    bool isBinaryPalindrome(const uint8_t *data, int bits) {
        for (int a = bits-1, b = 0; a > b; a--, b++) {
            bool ab = !!(data[a/8] & (1<<(a % 8)));
            bool bb = !!(data[b/8] & (1<<(b % 8)));
            if (ab != bb) {
                return false;
            }
        }

        return true;
    }

    bool isHexPalindrome(const uint8_t *data, int bits) {
        for (int a = (bits/8)-1, b = 0; a > b; a--, b++) {
            uint8_t an1 = (data[a] & 0xF0) >> 4;
            uint8_t an2 = data[a] & 0x0F;
            uint8_t bn1 = (data[b] & 0xF0) >> 4;
            uint8_t bn2 = data[b] & 0x0F;

            if (an1 != bn2 || an2 != bn1) {
                return false;
            }
        }

        return true;
    }

    bool isDecimalPalindrome(uint64_t data) {
        // TODO better way to do this? do bignum to find larger decimal palindromes?
        char buff[32];

        size_t len = snprintf(buff, sizeof(buff), "%ld", data);
        if (len <= sizeof(buff)) {
            for (int i = len-1, j = 0; i > j; i--, j++) {
                if (buff[i] != buff[j]) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
};


static class Palindromes palindromes;
