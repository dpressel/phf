/* ==========================================================================
 * phf.cc - Tiny perfect hash function library.
 * --------------------------------------------------------------------------
 * Copyright (c) 2014-2015, 2019  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#include <limits.h>   /* CHAR_BIT SIZE_MAX */
#include <inttypes.h> /* PRIu32 PRIu64 PRIx64 */
#include <stdint.h>   /* UINT32_C UINT64_C uint32_t uint64_t */
#include <stdlib.h>   /* abort(3) calloc(3) free(3) qsort(3) */
#include <string.h>   /* memset(3) */
#include <errno.h>    /* errno */
#include <assert.h>   /* assert(3) */

#include <algorithm>   /* std::sort */
#include <iterator>    /* std::begin std::end */
#include <new>         /* std::nothrow */
#include <string>      /* std::string */
#include <type_traits> /* std::is_standard_layout std::is_trivial */
#include <utility>     /* std::move */

#include "phf.h"

#if PHF_MAIN

#include <stdlib.h>    /* arc4random(3) free(3) realloc(3) */
#include <stdio.h>     /* fclose(3) fopen(3) fprintf(3) fread(3) freopen(3) printf(3) */
#include <time.h>      /* CLOCKS_PER_SEC clock(3) */
#include <string.h>    /* strcmp(3) */
#include <sys/param.h> /* BSD */
#include <unistd.h>    /* getopt(3) */
#include <strings.h>   /* ffsl(3) */
#include <err.h>       /* err(3) errx(3) warnx(3) */

#ifndef HAVE_VALGRIND_MEMCHECK_H
#define HAVE_VALGRIND_MEMCHECK_H __has_include(<valgrind/memcheck.h>)
#endif

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

static uint32_t randomseed(void) {
#if __APPLE__
	/*
	 * As of macOS 10.13.6 ccaes_vng_ctr_crypt and drbg_update in
	 * libcorecrypto.dylib trigger a "Conditional jump or move on
	 * uninitialized value(s)". As of Valgrind 3.15.0.GIT (20190214)
	 * even when suppressed it still taints code indirectly conditioned
	 * on the seed value.
	 */
	uint32_t seed = arc4random();
	#ifdef VALGRIND_MAKE_MEM_DEFINED
	VALGRIND_MAKE_MEM_DEFINED(&seed, sizeof seed);
	#else
	#warning unable to suppress CoreCrypto CSPRNG uninitialized value tainting
	#endif
	return seed;
#elif defined BSD /* catchall for modern BSDs, which all have arc4random */
	return arc4random();
#else
	FILE *fp;
	uint32_t seed;

	if (!(fp = fopen("/dev/urandom", "r")))
		err(1, "/dev/urandom");

	if (1 != fread(&seed, sizeof seed, 1, fp))
		err(1, "/dev/urandom");

	fclose(fp);

	return seed;
#endif
} /* randomseed() */


template<typename T>
static void pushkey(T **k, size_t *n, size_t *z, T kn) {
	if (!(*n < *z)) {
		size_t z1 = PHF_MAX(*z, 1) * 2;
		T *p;

		if (!std::is_trivially_copyable<T>::value) {
			int error;

			if ((error = phf_calloc(&p, z1)))
				errx(1, "calloc: %s", strerror(error));
			for (size_t i = 0; i < *n; i++)
				p[i] = std::move((*k)[i]);
			phf_freearray(*k, *z);

			goto commit;
		}
		if (z1 < *z || (SIZE_MAX / sizeof **k) < z1)
			errx(1, "addkey: %s", strerror(ERANGE));

		if (!(p = (T *)realloc(*k, z1 * sizeof **k)))
			err(1, "realloc");

commit:
		*k = p;
		*z = z1;
	}

	(*k)[(*n)++] = std::move(kn);
} /* pushkey() */


template<typename T>
static void addkey(T **k, size_t *n, size_t *z, const char *src) {
	pushkey(k, n, z, static_cast<T>(strtoull(src, NULL, 0)));
} /* addkey() */

static void addkey(phf_string_t **k, size_t *n, size_t *z, char *src, size_t len) {
	phf_string_t kn = { (void *)src, len };
	pushkey(k, n, z, kn);
} /* addkey() */

static void addkey(phf_string_t **k, size_t *n, size_t *z, char *src) {
	addkey(k, n, z, src, strlen(src));
} /* addkey() */

static void addkey(std::string **k, size_t *n, size_t *z, char *src, size_t len) {
	pushkey(k, n, z, std::string(src, len));
} /* addkey() */

static void addkey(std::string **k, size_t *n, size_t *z, char *src) {
	addkey(k, n, z, src, strlen(src));
} /* addkey() */

template<typename T>
static void addkeys(T **k, size_t *n, size_t *z, char **src, int count) {
	for (int i = 0; i < count; i++)
		addkey(k, n, z, src[i]);
} /* addkey() */

template<typename T>
static void addkeys(T **k, size_t *n, size_t *z, FILE *fp, char **data) {
	char *ln = NULL;
	size_t lz = 0;
	ssize_t len;

	(void)data;

	while ((len = getline(&ln, &lz, fp)) > 0) {
		if (--len > 0) {
			if (ln[len] == '\n')
				ln[len] = '\0';
			addkey(k, n, z, ln);
		}
	}
	
	free(ln);
} /* addkeys() */

/* slurp file into a single string and take pointers */
static void addkeys(phf_string_t **k, size_t *n, size_t *z, FILE *fp, char **data) {
	size_t p = 0, pe = 0, tp;
	char buf[BUFSIZ], *tmp;
	size_t buflen;

	while ((buflen = fread(buf, 1, sizeof buf, fp))) {
		if (buflen > (pe - p)) {
			if (~buflen < pe || 0 == (pe = phf_powerup(buflen + pe)))
				errx(1, "realloc: %s", strerror(ERANGE));
			if (!(tmp = (char *)realloc(*data, pe)))
				err(1, "realloc");
			*data = tmp;
		}

		memcpy(*data + p, buf, buflen);
		p += buflen;
	}

	for (pe = p, p = 0; p < pe; ) {
		while (p < pe && (*data)[p] == '\n')
			p++;

		tp = p;

		while (p < pe && (*data)[p] != '\n')
			p++;
				
		if (p > tp)
			addkey(k, n, z, &(*data)[tp], (size_t)(p - tp));
	}
} /* addkeys() */


static inline void printkey(phf_string_t &k, phf_hash_t hash) {
	printf("%-32.*s : %" PHF_PRIuHASH "\n", (int)k.n, (char *)k.p, hash);
} /* printkey() */

static inline void printkey(std::string &k, phf_hash_t hash) {
	printf("%-32s : %" PHF_PRIuHASH "\n", k.c_str(), hash);
} /* printkey() */

template<typename T>
static inline void printkey(T k, phf_hash_t hash) {
	printf("%llu : %" PHF_PRIuHASH "\n", (unsigned long long)k, hash);
} /* printkey() */

template<typename T, bool nodiv>
static inline void exec(int argc, char **argv, size_t lambda, size_t alpha, size_t seed, bool verbose, bool noprint) {
	T *k = NULL;
	size_t n = 0, z = 0;
	char *data = NULL;
	struct phf phf;
	clock_t begin, end;

	addkeys(&k, &n, &z, argv, argc);
	addkeys(&k, &n, &z, stdin, &data);

	size_t m = PHF::uniq(k, n);
	if (verbose)
		warnx("loaded %zu keys (%zu duplicates)", m, (n - m));
	n = m;

	begin = clock();
	PHF::init<T, nodiv>(&phf, k, n, lambda, alpha, seed);
	end = clock();


	if (verbose) {
		warnx("found perfect hash for %zu keys in %fs", n, (double)(end - begin) / CLOCKS_PER_SEC);

		begin = clock();
		PHF::compact(&phf);
		end = clock();
		warnx("compacted displacement map in %fs", (double)(end - begin) / CLOCKS_PER_SEC);

		int d_bits = ffsl((long)phf_powerup(phf.d_max));
		double k_bits = ((double)phf.r * d_bits) / n;
		double g_load = (double)n / phf.r;
		warnx("r:%zu m:%zu d_max:%zu d_bits:%d k_bits:%.2f g_load:%.2f", phf.r, phf.m, phf.d_max, d_bits, k_bits, g_load);

		size_t x = 0;
		begin = clock();
		for (size_t i = 0; i < n; i++) {
			x += PHF::hash(&phf, k[i]);
		}
		end = clock();
		warnx("hashed %zu keys in %fs (x:%zu)", n, (double)(end - begin) / CLOCKS_PER_SEC, x);
	}

	if (!noprint) {
		for (size_t i = 0; i < n; i++) {
			printkey(k[i], PHF::hash(&phf, k[i]));
		}
	}

	PHF::destroy(&phf);
	free(data);
	phf_freearray(k, n);
} /* exec() */

static void printprimes(int argc, char **argv) {
	intmax_t n = 0, m = UINT32_MAX;
	char *end;

	if (argc > 0) {
		n = strtoimax(argv[0], &end, 0);
		if (end == argv[0] || *end != '\0' || n < 0 || n > UINT32_MAX)
			errx(1, "%s: invalid number", argv[0]);
		n = PHF_MAX(n, 2);
	}

	if (argc > 1) {
		m = strtoimax(argv[1], &end, 0);
		if (end == argv[1] || *end != '\0' || m < n || m > UINT32_MAX)
			errx(1, "%s: invalid number", argv[1]);
	}

	for (; n <= m; n++) {
		if (phf_isprime(n))
			printf("%" PRIdMAX "\n", n);
	}
} /* printprimes() */

int main(int argc, char **argv) {
	const char *path = "/dev/null";
	size_t lambda = 4;
	size_t alpha = 80;
	uint32_t seed = randomseed();
	bool verbose = 0;
	bool noprint = 0;
	bool nodiv = 0;
	enum {
		PHF_UINT32,
		PHF_UINT64,
		PHF_STRING,
		PHF_STD_STRING
	} type = PHF_UINT32;
	bool primes = 0;
	extern char *optarg;
	extern int optind;
	int optc;

	while (-1 != (optc = getopt(argc, argv, "f:l:a:s:2t:nvph"))) {
		switch (optc) {
		case 'f':
			path = optarg;
			break;
		case 'l':
			lambda = strtoul(optarg, NULL, 0);
			break;
		case 'a':
			alpha = strtoul(optarg, NULL, 0);
			break;
		case 's':
			seed = strtoul(optarg, NULL, 0);
			break;
		case '2':
			nodiv = 1;
			break;
		case 't':
			if (!strcmp(optarg, "uint32")) {
				type = PHF_UINT32;
			} else if (!strcmp(optarg, "uint64")) {
				type = PHF_UINT64;
			} else if (!strcmp(optarg, "string")) {
				type = PHF_STRING;
			} else if (!strcmp(optarg, "std::string")) {
				type = PHF_STD_STRING;
			} else {
				errx(1, "%s: invalid key type", optarg);
			}

			break;
		case 'n':
			noprint = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'p':
			primes = 1;
			break;
		case 'h':
			/* FALL THROUGH */
		default:
			fprintf(optc == 'h'? stdout : stderr,
				"%s [-f:l:a:s:t:2nvph] [key [...]]\n"
				"  -f PATH  read keys from PATH (- for stdin)\n"
				"  -l NUM   number of keys per displacement map bucket (reported as g_load)\n"
				"  -a PCT   hash table load factor (1%% - 100%%)\n"
				"  -s SEED  random seed\n"
				"  -t TYPE  parse and hash keys as uint32, uint64, string, or std::string\n"
				"  -2       avoid modular division by rounding r and m to power of 2\n"
				"  -n       do not print key-hash pairs\n"
				"  -v       report hashing status\n"
				"  -p       operate like primes(3) utility\n"
				"  -h       print usage message\n"
				"\n"
				"Report bugs to <william@25thandClement.com>\n",
				argv[0]
			);

			return optc == 'h'? 0 : 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (primes)
		return printprimes(argc, argv), 0;

	if (strcmp(path, "-") && !freopen(path, "r", stdin))
		err(1, "%s", path);

	switch (type) {
	case PHF_UINT32:
		if (nodiv)
			exec<uint32_t, true>(argc, argv, lambda, alpha, seed, verbose, noprint);
		else
			exec<uint32_t, false>(argc, argv, lambda, alpha, seed, verbose, noprint);
		break;
	case PHF_UINT64:
		if (nodiv)
			exec<uint64_t, true>(argc, argv, lambda, alpha, seed, verbose, noprint);
		else
			exec<uint64_t, false>(argc, argv, lambda, alpha, seed, verbose, noprint);
		break;
	case PHF_STRING:
		if (nodiv)
			exec<phf_string_t, true>(argc, argv, lambda, alpha, seed, verbose, noprint);
		else
			exec<phf_string_t, false>(argc, argv, lambda, alpha, seed, verbose, noprint);
		break;
	case PHF_STD_STRING:
		if (nodiv)
			exec<std::string, true>(argc, argv, lambda, alpha, seed, verbose, noprint);
		else
			exec<std::string, false>(argc, argv, lambda, alpha, seed, verbose, noprint);
		break;
	}

	return 0;
} /* main() */

#endif /* PHF_MAIN */
