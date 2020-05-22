// bitarray operations
typedef struct
{
    unsigned bits;          // number of represented bits
    unsigned set;           // count of set bits
    unsigned char array[];  // zero length array
} bitarray;

// return 1 if numbered bit is set, 0 if clear, -1 if bit number is invalid
int bitarray_test(bitarray *b, unsigned bit);

// Set numbered bit and return 0, or -1 if bit number is invalid
int bitarray_set(bitarray *b, unsigned bit);

// Reset numbered bit and return 0, or -1 if bit number is invalod
int bitarray_clear(bitarray *b, unsigned bit);

// clear all bits
void bitarray_init(bitarray *b);

// create new bit array and return pointer, or NULL if OOM
// caller must free when done
bitarray *bitarray_create(unsigned bits);

// Given a bit number, the next highest set bit (or that bit, if it's set).
// Or return -1 if none.
int bitarray_next(bitarray *b, unsigned bit);
