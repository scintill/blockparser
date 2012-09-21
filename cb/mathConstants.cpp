#include <stdio.h>
#include <string.h>

#include "callback.h"
#include "util.h"
#include "bignum.h"


enum  optionIndex { kUnknown };
static const option::Descriptor usageDescriptor[] =
{
    { kUnknown, 0, "", "", option::Arg::None, "\n\n        dump mathematical constants found (pi, e, sqrt 2, etc.)\n" },
    { 0,        0,  0,  0,                 0,        0    }
};

// how many digits of the constants to look for
#define INTERESTING_DIGITS_THRESHOLD 8

typedef struct {
    const char *name;
    const char *digits;
} MathConstant;

MathConstant mathConstants[] = {
    { "pi", "3141592653589793238462643383279502884197" },
    { "e", "2718281828459045235360287471352662497757" },
    { "sqrt(2)", "1414213562373095048801688724209698078569" }
};

class MathConstants : public Callback {
    virtual void startTX(const uint8_t *p, const uint8_t *hash) {
        checkConstants(hash, 256, "Txid");
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

        checkConstants(pubKeyHash.v, 160, "Pubkey hash");
        checkConstants(value, "Tx value");
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

    virtual void startBlock(const Block *b) {
        const uint8_t *p = b->data;

        sha256Twice(this->curBlockHash, p, 80);
        SKIP(uint32_t, version, p);
        SKIP(uint256_t, prevBlkHash, p);
        LOAD(uint256_t, blkMerkleRoot, p);
        LOAD(uint32_t, bTime, p);
        LOAD(uint32_t, nNonce, p);

        checkConstants(this->curBlockHash, 256, "Block hash");
        checkConstants(&blkMerkleRoot.v[0], 256, "Block merkle root");
        checkConstants((uint8_t*)&bTime, 32, "Block timestamp");
        checkConstants((uint8_t*)&nNonce, 32, "Block nonce");
    }

    virtual const char *name() const {
        return "mathConstants";
    }

    virtual const option::Descriptor *usage() const {
        return usageDescriptor;
    }

    virtual bool needTXHash() { return true; }

    private:
    uint8_t curBlockHash[kSHA256ByteSize];

    void checkConstants(uint64_t data, const char *tag) {
        char buff[64];
        snprintf(buff, sizeof(buff), "%ld", data);

        checkConstants(buff, tag);
    }

    void checkConstants(const uint8_t *data, int bits, const char *tag) {
        char decStr[100];
        bignum n;
        byte_arr_to_bignum((unsigned char*)data, bits/8, &n);
        bignum_to_str(&n, decStr, sizeof(decStr));

        checkConstants(decStr, tag);
    }

    void checkConstants(char *decStr, const char *tag) {
        char constantStr[INTERESTING_DIGITS_THRESHOLD+1];
        constantStr[sizeof(constantStr)-1] = '\0';
        char *found;

        int n = sizeof(mathConstants) / sizeof(mathConstants[0]);
        for (int i = 0; i < n; i++) {
            strncpy(constantStr, mathConstants[i].digits, INTERESTING_DIGITS_THRESHOLD);
            //printf("check %s for %s (%s)\n", decStr, constantStr, mathConstants[i].name);
            if ((found = strstr(decStr, constantStr))) {
                printf("%s: %s in ", tag, mathConstants[i].name);

                char c;
                c = *found;
                *found = '\0';
                printf("%s[b]", decStr);
                *found = c;
                c = found[INTERESTING_DIGITS_THRESHOLD];
                found[INTERESTING_DIGITS_THRESHOLD] = '\0';
                printf("%s[/b]", found);
                found[INTERESTING_DIGITS_THRESHOLD] = c;
                printf("%s", &found[INTERESTING_DIGITS_THRESHOLD]);

                printf("; block ");
                showHex(curBlockHash);
                printf("\n");
            }
        }
    }

};


static class MathConstants mathConstantsCallBack;
