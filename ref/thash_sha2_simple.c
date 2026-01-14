#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sha2.h"
#include "quick_sha256.h"
#include "quick_sha512.h"

#if SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
#if SPX_SHA512
    if (inblocks > 1) {
	thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif

    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    SHA256_CTX sha2_state;
    sha256_init(&sha2_state);
    sha256_update(&sha2_state, (unsigned char *)addr, SPX_SHA256_ADDR_BYTES);
    sha256_update(&sha2_state, in, inblocks*SPX_N);
    sha256_final(&sha2_state, outbuf);
    memcpy(out, outbuf, SPX_N);
}

#if SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    SHA512_CTX sha2_state;
    sha512_init(&sha2_state);
    sha512_update(&sha2_state, (unsigned char *)addr, SPX_SHA256_ADDR_BYTES);
    sha512_update(&sha2_state, in, inblocks*SPX_N);
    sha512_final(&sha2_state, outbuf);
    memcpy(out, outbuf, SPX_N);
}
#endif
