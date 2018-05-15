#include <stdint.h>


static char *g_hex_chars = "0123456789abcdef";


int size_of_bytes(int hexlen)
{
    return (hexlen & 1) ? (hexlen + 1) / 2 : hexlen / 2;
}


static uint8_t char_to_hex(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return 255;
}


int hex_to_bytes(const char *buf, int len, uint8_t *out, int outbuf_size)
{
    int i = len - 1;
    int out_len = (len & 1) ? (len + 1) / 2 : len / 2;
    int j = out_len - 1;

    if (j > outbuf_size) {
        return -1; /* Output buffer is smaller than need */
    }

    while (i >= 0) {
        out[j] = char_to_hex(buf[i--]);
        if (i >= 0) {
            out[j--] |= char_to_hex(buf[i--]) << 4;
        }
    }

    return out_len;
}


void bytes_to_hex(uint8_t *buffer, int len, char *out)
{
    int i = 0;
    int j = 0;

    while (j < len) {
        out[i++] = g_hex_chars[(buffer[j] >> 4) & 0xF];
        out[i++] = g_hex_chars[buffer[j] & 0xF];
        j++;
    }

    out[i] = '\0';
}
