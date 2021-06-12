# Introduction #

This is a simple implementation of the CHD perfect hash algorithm. CHD can
generate perfect hash functions for very large key sets--on the order of
millions of keys--in a very short time. On my circa 2012 desktop and using
the default parameters (hash load factor of 80% and average displacement map
bucket load of 4.0 keys) this implementation can generate a hash function
for 1,000 keys in less than 1/100th of a second, and 1,000,000 keys in less
than a second.

For more information about the algorithm, see
http://cmph.sourceforge.net/chd.html.

# Dependencies #

* No runtime dependencies.
* Requires a modern C++ compiler to build.
* Single header file

# About this fork #

This fork targets C++ only and removes comditional compilation switches for Lua or C++ only.  The goal is a minimalistic version of the original library as a single header.  This also removes the optional sample from the original codebase, and its associated helper functions

### Compilation ###

## C++ ##

## API ##

### PHF::uniq<T>(T k[], size_t n); ###

Similar to the shell command `sort | uniq`. Sorts, deduplicates, and shifts
down the keys in the array k. Returns the number of unique keys, which will
have been moved to the beginning of the array. If necessary do this before
calling PHF::init, as PHF::init does not tolerate duplicate keys.

### int PHF::init<T, nodiv>(struct phf *f, const T k[], size_t n, size_t l, size_t a, phf_seed_t s);

Generate a perfect hash function for the n keys in array k and store the
results in f. Returns a system error number on failure, or 0 on success. f
is unmodified on failure.

### void PHF::destroy(struct phf *);

Deallocates internal tables, but not the struct object itself.

### void PHF::compact<T, nodiv>(struct phf *);

By default the displacement map is an array of uint32_t integers. This
function will select the smallest type necessary to hold the largest
displacement value and update the internal state accordingly. For a loading
factor of 80% (0.8) in the output hash space, and displacement map loading
factor of 4 (400%), the smallest primitive type will often be uint8_t.

### phf_hash_t PHF::hash<T>(struct phf *f, T k);

Returns an integer hash value, h, where 0 <= h < f->m. h will be unique for
each unique key provided when generating the function. f->m will be larger
than the number of unique keys and is based on the specified loading factor
(alpha), rounded up to the nearest prime or nearest power of 2, depending on
the mode of modular reduction selected. For example, for a loading factor of
80% m will be 127: 100 is 80% of 125, and 127 is the closest prime greater
than or equal to 125. With the nodiv option, m would be 128: 100 is 80% of
125, and 128 is the closest power of 2 greater than or equal to 125.

