#include <stdio.h>
#include <stdint.h>
#include "crypto.h"


static char *g_from_prikey = "82886368e13da59ed6f263018e9f900bb5cbf425148f5d720c7a980caf5aeba8";
static char *g_from_address = "dbff28264d2fd6bbda6be7e2a647ae1905692f52";
static char *g_from_pubkey = "9f98e27be5f44e18433ad68d2a6a49ae3397e4979a607b2b210423a2f3e1763c86121f47b648910eb79a048dd904f4730a5066afc74300cdafebb0596491d65b";


void sign_test(void)
{
    void *context;
    uint8_t prikey[65];
    uint8_t pubkey[131];
    uint8_t address[41];
    uint8_t rlp_tx[8192];

    context = create_context();
    if (context == NULL) {
        return;
    }

    if (!create_account(context, prikey, 65, pubkey, 131, address, 41)) {
        printf("create_account failed\n");
        destroy_context(context);
        return;
    }

    printf("prikey: %s\n", prikey);
    printf("pubkey: %s\n", pubkey);
    printf("address: %s\n", address);

    sign_transaction(context, g_from_prikey, "71", (char *)address, "1", "5208", "f", "", rlp_tx);
    printf("rlp_tx: %s\n", rlp_tx);

    destroy_context(context);
}


int main(void)
{
    sign_test();

    return 0;
}
