#include <stdio.h>
#include "otpgen.h"

/*
Compile:
    gcc otpgen.c -o otpgen -lssl -lcrypto -lm
Compile Static (Not working)
    gcc otpgen.c -o otpgen-static -lssl -lcrypto -lm -ldl -lpthread -static -s

How to Get Key:
    ./gauth-export-parser gauth-exported-qrcode-value.txt

*/

static unsigned char secret[] = {
    0x6B, 0x44, 0x87, 0x6B, 0x06, 0xCC, 0x5C, 0x83, 0xC0, 0x5A};

int main(int argc, char const *argv[])
{
    uint32_t result;
    // Validity 30 second
    time_t t = get_time(0);
    // 6 DIGITS
    result = TOTP(secret, sizeof(secret), t, 6);
    printf("%u\n", result);
    return 0;
}
