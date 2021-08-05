#include <string.h>
#include <stdlib.h>
#include "bitarray.h"

// Bit array operations

// Return 1 if numbered bit is set, 0 if reset, -1 if bit number is invalid
int bitarray_test(bitarray *b, unsigned bit)
{
    if (bit >= b->bits) return -1;
    return b->array[bit/8] & (1 << (bit & 7)) ? 1 : 0;
}

// Set numbered bit and return 0, or -1 if bit number is invalid
// Track the number of bits set.
int bitarray_set(bitarray *b, unsigned bit)
{
    if (bit >= b->bits) return -1;
    if (!bitarray_test(b, bit))
    {
        b->numset++;
        b->array[bit/8] |= (1 << (bit & 7));
    }
    return 0;
}

// Reset numbered bit and return 0, or -1 if bit number is invalid
// Track the number of bits set.
int bitarray_reset(bitarray *b, unsigned bit)
{
    if (bit >= b->bits) return -1;
    if (bitarray_test(b, bit))
    {
        b->numset--;
        b->array[bit/8] &= ~(1 << (bit & 7));
    }
    return 0;
}

// Clear all bits in the array
void bitarray_wipe(bitarray *b)
{
    memset(b->array, 0, (b->bits+7)/8);
    b->numset = 0;
}

// Create new bit array and return pointer, or NULL if OOM.
// Caller must free() it when done.
bitarray *bitarray_create(unsigned bits)
{
    bitarray *b = malloc(sizeof(bitarray)+((bits+7)/8));
    if (b)
    {
        b->bits = bits;
        bitarray_wipe(b);
    }
    return b;
}

// Return number of set bits in the bitarray
int bitarray_numset(bitarray *b)
{
    return b->numset;
}

// Given a bit number, return that bit if it's set, else the number of the next
// highest set bit. Or return -1 if none.
int bitarray_next(bitarray *b, unsigned bit)
{
    if (bit >= b->bits || !b->numset) return -1;
    if (b->array[bit/8] < 1 << (bit & 7))
    {
        bit = (bit & ~7) + 8;
        while (1)
        {
            if (bit >= b->bits) return -1;
            if (b->array[bit/8]) break;
            bit += 8;
        }
    }
    while (!(b->array[bit/8] & (1 << (bit & 7)))) bit++;
    return bit;
}
