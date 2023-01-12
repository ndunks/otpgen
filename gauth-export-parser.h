#ifndef GAUTH_EXPORT_PARSER
#define GAUTH_EXPORT_PARSER
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define PB_WIRE_TYPE_VARINT 0 //	int32, int64, uint32, uint64, sint32, sint64, bool, enum
#define PB_WIRE_TYPE_I64 1    //	fixed64, sfixed64, double
#define PB_WIRE_TYPE_LEN 2    //	string, bytes, embedded messages, packed repeated fields
#define PB_WIRE_TYPE_SGROUP 3 //	group start (deprecated)
#define PB_WIRE_TYPE_EGROUP 4 //	group end (deprecated)
#define PB_WIRE_TYPE_I32 5    //	fixed32, sfixed32, float

/**
 * Protobuf structure:
message Payload {
  repeated OtpParameters otp_parameters = 1;
  int32 version = 2;
  int32 batch_size = 3;
  int32 batch_index = 4;
  int32 batch_id = 5;
}
*/

typedef enum _migration_algorithm
{
    UNSPECIFIED_ALGORITHM = 0,
    SHA1 = 1,
    SHA256 = 2,
    SHA512 = 3,
    MD5 = 4
} migration_algorithm;
typedef enum _migration_digitcount
{
    UNSPECIFIED_DIGITCOUNT = 0,
    SIX = 1,
    EIGHT = 2
} migration_digitcount;
typedef enum _migration_otptype
{
    UNSPECIFIED_OTPTYPE = 0,
    HOTP = 1,
    TOTP = 2
} migration_otptype;

typedef struct _migration_parameters
{
    char secret[512];                  // tag: 1
    uint32_t secret_len;
    char name[512];                    // tag: 2
    char issuer[512];                  // tag: 3
    migration_algorithm algorithm; // tag: 4
    migration_digitcount digits;   // tag: 5
    migration_otptype type;        // tag: 6
} migration_parameters;

// https://github.com/tidwall/varint.c/blob/master/varint.c
// varint_read_u reads a uint64 varint from data.
// Returns the number of bytes reads, or returns 0 if there's not enough data
// to complete the read, or returns -1 if the data buffer does not represent
// a valid uint64 varint.
int varint_read_u(const char *str, uint32_t *x)
{
    uint32_t b;
    *x = 0;

    b = str[0];
    *x |= (b & 0x7f) << (7 * 0);
    if (b < 0x80)
        return 0 + 1;

    b = str[1];
    *x |= (b & 0x7f) << (7 * 1);
    if (b < 0x80)
        return 1 + 1;

    b = str[2];
    *x |= (b & 0x7f) << (7 * 2);
    if (b < 0x80)
        return 2 + 1;

    b = str[3];
    *x |= (b & 0x7f) << (7 * 3);
    if (b < 0x80)
        return 3 + 1;

    return -1;
}

void DumpHex(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            printf(" ");
            if ((i + 1) % 16 == 0)
            {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}
/* https://github.com/abejfehr/URLDecode/blob/master/urldecode.c */
char *urlDecode(const char *str)
{
    int d = 0; /* whether or not the string is decoded */

    char *dStr = (char *)malloc(strlen(str) + 1);
    char eStr[] = "00"; /* for a hex code */

    strcpy(dStr, str);

    while (!d)
    {
        d = 1;
        int i; /* the counter for the string */

        for (i = 0; i < strlen(dStr); ++i)
        {

            if (dStr[i] == '%')
            {
                if (dStr[i + 1] == 0)
                    return dStr;

                if (isxdigit(dStr[i + 1]) && isxdigit(dStr[i + 2]))
                {

                    d = 0;

                    /* combine the next to numbers into one */
                    eStr[0] = dStr[i + 1];
                    eStr[1] = dStr[i + 2];

                    /* convert it to decimal */
                    long int x = strtol(eStr, NULL, 16);

                    /* remove the hex */
                    memmove(&dStr[i + 1], &dStr[i + 3], strlen(&dStr[i + 3]) + 1);

                    dStr[i] = x;
                }
            }
        }
    }

    return dStr;
}
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

/* https://stackoverflow.com/a/6782480/6682759 */
unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length)
{
    char decoding_table[256];
    // build decoding_table
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char)encoding_table[i]] = i;

    if (input_length % 4 != 0)
        return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=')
        (*output_length)--;
    if (data[input_length - 2] == '=')
        (*output_length)--;

    unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
    if (decoded_data == NULL)
        return NULL;

    for (int i = 0, j = 0; i < input_length;)
    {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_length)
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}
#endif