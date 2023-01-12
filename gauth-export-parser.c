#include "gauth-export-parser.h"
#include "base32.h"

/*

Google Authenticator Parser

View value from exported GAuth QR Code content

Compile:
    gcc -o gauth-export-parser gauth-export-parser.c

Watch:
    while true
        do gcc -o gauth-export-parser gauth-export-parser.c && ./gauth-export-parser sample/gauth-export.txt ;
        inotifywait -e close_write -q gauth-export-parser.c;
    done
*/

/** Data Protobuf structure:
 message OtpParameters {
    bytes secret = 1;
    string name = 2;
    string issuer = 3;
    Algorithm algorithm = 4;
    DigitCount digits = 5;
    OtpType type = 6;
    uint64 counter = 7;
}
message Payload {
    repeated OtpParameters otp_parameters = 1;
    int32 version = 2;
    int32 batch_size = 3;
    int32 batch_index = 4;
    int32 batch_id = 5;
} */
int gauth_decode_otp_migration(const u_char *input, size_t size)
{
    size_t decoded_size, ofs = 0, i;
    u_char ilen;
    char *url_decoded, *msg, *data_start, *data,
        *eof, encoded_secret[512];
    migration_parameters item;
    int type, tag, varint_read_len;
    uint32_t len;
    url_decoded = urlDecode(input);
    size = strlen(url_decoded);
    // printf("Parsing (%i): %s\n", size, url_decoded);
    data = base64_decode(url_decoded, size, &decoded_size);
    free((void *)url_decoded);
    data_start = data;
    eof = data + decoded_size;
    // this is just dead simple hardcoded protobuf read.
    // the data is repeated (array) of message with type OtpParameters
    while ((uint64_t)data < (uint64_t)eof)
    {
        // read tag & type
        type = (*data) & 0b111;
        tag = (*data) >> 3; // tag is varint, but in this case the value is small.
        data++;

        // printf("type %d, tag %d\n", type, tag);
        switch (tag)
        {
        case 1: // its len based
            if (type != PB_WIRE_TYPE_LEN)
            {
                printf("Invalid type in field 1 (otp_parameters)\n");
                return 1;
            }
            varint_read_len = varint_read_u(data, &len);
            // printf("LEN %i + %i \n", varint_read_len, len);

            data += varint_read_len;
            msg = data; // message part
            data += len;
            memset(&item, 0, sizeof(item));
            while ((uint64_t)msg < (uint64_t)data)
            {
                type = (*msg) & 0b111;
                tag = (*msg) >> 3; // tag is varint, but in this case the value is small.
                msg++;
                // printf("MSG: type %d, tag %d\n", type, tag);
                switch (tag)
                {
                case 1: // secret
                    varint_read_len = varint_read_u(msg, &item.secret_len);
                    msg += varint_read_len;
                    memcpy(item.secret, msg, item.secret_len);
                    base32_encode(item.secret, item.secret_len, encoded_secret);
                    printf("secret: ", item.secret_len);
                    for (i = 0; i < item.secret_len; i++)
                    {
                        printf("0x%02X, ", (u_char)item.secret[i]);
                    }

                    printf("\n");
                    msg += item.secret_len;
                    break;
                case 2: // name
                    varint_read_len = varint_read_u(msg, &len);
                    msg += varint_read_len;
                    memcpy(item.name, msg, len);
                    printf("name  : %s\n", item.name);
                    msg += len;
                    break;
                case 3: // issuer
                    varint_read_len = varint_read_u(msg, &len);
                    msg += varint_read_len;
                    memcpy(item.issuer, msg, len);
                    printf("issuer: %s\n", item.issuer);
                    msg += len;
                    break;
                case 4: // algorithm
                    varint_read_len = varint_read_u(msg, (uint32_t *)&item.algorithm);
                    msg += varint_read_len;
                    break;
                case 5: // digits
                    varint_read_len = varint_read_u(msg, (uint32_t *)&item.digits);
                    msg += varint_read_len;
                    break;
                case 6: // type
                    varint_read_len = varint_read_u(msg, (uint32_t *)&item.type);
                    msg += varint_read_len;
                    break;
                default:
                    printf("Invalid in msg or has new tag: %i, field: %i ?\n", tag, type);
                    return 1;
                    break;
                }
            }
            printf("----------------------\n");
            break;

        default: // its varint
            if (type == PB_WIRE_TYPE_VARINT && tag >= 2 && tag <= 5)
            {
                varint_read_len = varint_read_u(data, &len);
                data += varint_read_len;
                if (tag == 2)
                {
                    printf("version: %d\n", len);
                }
                else if (tag == 3)
                {
                    printf("batch_size: %d\n", len);
                }
                else if (tag == 4)
                {
                    printf("batch_index: %d\n", len);
                }
                else // tag == 5
                {
                    printf("batch_id: %d\n", len);
                }
            }
            else
            {
                printf("Invalid data or has new tag: %i, field: %i ?\n", tag, type);
            }
            break;
        }
    }
    free((void *)data_start);
    printf("\n---DONE---\n");
    return 0;
}

int main(int argc, char const *argv[])
{
    const char *data, data_pattern[] = "otpauth-migration://offline?data=";
    char buffer[4096];
    size_t size, data_pattern_len = sizeof(data_pattern) - 1;
    FILE *fd;

    if (argc <= 1)
    {
        printf("No file/data to read\n");
        return 1;
    }

    if (strncmp(argv[1], data_pattern, data_pattern_len) != 0)
    {
        fd = fopen(argv[1], "r");
        if (fd <= 0)
        {
            printf("Failed opening file: %s\n", argv[1]);
            return 1;
        }

        size = fread(buffer, sizeof(char), sizeof(buffer), fd);

        if (!feof(fd))
        {
            printf("Not fully read\n");
            return 1;
        }
        fclose(fd);
        if (strncmp(buffer, data_pattern, data_pattern_len) != 0)
        {
            printf("Invalid content, data must be started with %.*s\n", data_pattern_len, data_pattern);
            return 1;
        }
        data = &buffer[data_pattern_len];
        size -= data_pattern_len;
    }
    else
    {
        size = strlen(argv[1]) - data_pattern_len;
        data = (char *)(((char *)&argv[1]) + data_pattern_len);
    }

    if (size <= 0)
    {
        printf("Invalid data length\n");
        return 1;
    }

    return gauth_decode_otp_migration(data, size);
}
