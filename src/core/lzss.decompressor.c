#pragma once
#include <string.h>
#include <stdio.h>

#define HISTORYBUF_SIZE (1 << 12) /* 4 KB */

#define cyclic_inc(var, limit) \
        ((var + 1) < limit) ? (var += 1) : (var = 0)

#define wrap(value, limit) \
        (value < limit) ? value : (value - limit)

// Global variables for the bit reading process
static const unsigned char* input_ptr;
static size_t input_position;
static size_t input_size;
static int mask = 0;
static int in_byte = 0;

// Global variables for the output process
static unsigned char* output_ptr;
static size_t output_position;

/* get n bits from input buffer, but n <= sizeof(int) */
static int get_bit(unsigned int n)
{
    int bit_buffer = 0;
    int bits_read = 0;

    while (bits_read < n) {
        if (mask == 0) {
            if (input_position >= input_size) {
                if (bits_read == 0) return EOF;
                break;
            }
            in_byte = input_ptr[input_position++];
            mask = 0x80;
        }

        bit_buffer = (bit_buffer << 1) | ((in_byte & mask) ? 1 : 0);
        mask >>= 1;
        bits_read++;
    }

    return bit_buffer;
}

int lz_decompress(const unsigned char* input_buffer, size_t input_size_param,
                 unsigned char* output_buffer, size_t* output_size)
{
    unsigned char history_buf[HISTORYBUF_SIZE];
    unsigned int historybuf_head = 0;
    unsigned char temp_history_buf[15];
    
    // Initialize global variables
    input_ptr = input_buffer;
    input_position = 0;
    input_size = input_size_param;
    output_ptr = output_buffer;
    output_position = 0;
    mask = 0;
    
    memset(history_buf, 0, sizeof(unsigned char) * HISTORYBUF_SIZE);

    unsigned int c = 0;
    int offset = 0, len = 0;

    while ((c = get_bit(1)) != EOF)
    {
        if (c)
        {
            if ((c = get_bit(8)) == EOF) break;
            output_ptr[output_position++] = c;
            history_buf[historybuf_head] = c;
            cyclic_inc(historybuf_head, HISTORYBUF_SIZE);
        }
        else
        {
            if ((offset = get_bit(12)) == EOF) break;
            if ((len = get_bit(4)) == EOF) break;

            for (unsigned int i = 0; i < len; i++)
            {
                c = history_buf[wrap((offset + i), HISTORYBUF_SIZE)];
                output_ptr[output_position++] = c;
                temp_history_buf[i] = c;
            }

            for (unsigned int i = 0; i < len; i++)
            {
                history_buf[historybuf_head] = temp_history_buf[i];
                cyclic_inc(historybuf_head, HISTORYBUF_SIZE);
            }
        }
    }

    *output_size = output_position;
    return 0;
}