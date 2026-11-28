/* A harmless console program used as a UPX fixture. */
#include <stdio.h>

static const char ledger[] =
    "Barnacle UPX ledger: 12 boxes of stationery, 3 crates of paper, 7 reams of labels.\n";

int main(void)
{
    int boxes = 0;
    for (const char *p = ledger; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            boxes += *p - '0';
        }
    }
    printf("%s", ledger);
    return boxes == 0;
}
