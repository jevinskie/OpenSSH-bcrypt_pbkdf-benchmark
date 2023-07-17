#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>

extern "C" int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
                            uint8_t *key, size_t keylen, unsigned int rounds);

const uint8_t salt[] = {0xa0, 0x95, 0x71, 0x17, 0x9f, 0x27, 0x2f, 0xdf,
                        0x8b, 0x7a, 0x09, 0x74, 0x0b, 0x4d, 0x03, 0xeb};
char pass[]          = "JtsDXcI7VQAMkOO2";
uint8_t key[]        = {
    0x8a, 0x28, 0x9a, 0xc3, 0x37, 0xd2, 0x03, 0x5a, 0x46, 0x8b, 0xff, 0xd1, 0x70, 0xcc, 0x5d, 0x91,
    0x05, 0xd5, 0x2b, 0xdf, 0x46, 0x2e, 0x50, 0x33, 0x32, 0x2d, 0x7a, 0xcf, 0x71, 0xcf, 0x6f, 0x2c,
    0x40, 0xdf, 0xa1, 0x14, 0x01, 0x89, 0x24, 0x06, 0xa3, 0x2f, 0x72, 0xfa, 0x2b, 0xc9, 0x39, 0x06,
    0x10, 0xf3, 0xdc, 0x6c, 0x47, 0x5c, 0x34, 0x71, 0x5e, 0x62, 0xee, 0x10, 0xb2, 0x34, 0x7d, 0x5a,
    0xd3, 0xc1, 0xe5, 0x56, 0x09, 0x86, 0x4b, 0xc0, 0x7c, 0x37, 0xc5, 0x7a, 0x2a, 0xee, 0x90, 0xd4,
    0x91, 0xbc, 0xae, 0x35, 0x9d, 0xe5, 0x76, 0x19, 0x59, 0x3b, 0x72, 0x92, 0x24, 0xcb, 0x96, 0x0e,
    0x7b, 0x36, 0xd3, 0x95, 0x1c, 0x0a, 0x57, 0xf9, 0xfe, 0xc5, 0x3a, 0x37, 0x0a, 0x95, 0x76, 0xa6,
    0xc7, 0xf6, 0x4d, 0x50, 0x7f, 0x98, 0x36, 0xa5, 0x8c, 0x2d, 0x1d, 0x4e, 0x84, 0xc3, 0x18, 0x62};

static inline void bench(unsigned int rounds) {
    int res = bcrypt_pbkdf(pass, sizeof(pass) - 1, salt, sizeof(salt), key, sizeof(key), rounds);
    if (res != 0) {
        fprintf(stderr, "bcrypt_pbkdf returned non-zero value: %d\n", res);
        exit(-100);
    }
}

static inline void timespec_diff(const struct timespec *a, const struct timespec *b,
                                 struct timespec *result) {
    result->tv_sec  = a->tv_sec - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

static inline double timespec_to_seconds(const struct timespec *ts) {
    return (double)ts->tv_sec + ((double)ts->tv_nsec / (double)1000000000L);
}

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <number of rounds> <number of runs>\n", getprogname());
        return -1;
    }

    unsigned long int long_rounds = std::strtoul(argv[1], NULL, 0);
    if (long_rounds == 0) {
        fprintf(stderr, "Couldn't convert round number from string '%s'\n", argv[1]);
        return -2;
    }
    if (long_rounds == ULONG_MAX && errno == ERANGE) {
        fprintf(stderr, "Couldn't convert round number from string '%s', it is out of range.\n",
                argv[1]);
        return -3;
    }
    if (long_rounds > UINT_MAX) {
        fprintf(stderr, "Couldn't convert round number from string '%s', it is out of range.\n",
                argv[1]);
        return -4;
    }
    unsigned int rounds = (unsigned int)long_rounds;

    unsigned long int runs = std::strtoul(argv[2], NULL, 0);
    if (runs == 0) {
        fprintf(stderr, "Couldn't convert runs number from string '%s'\n", argv[2]);
        return -5;
    }
    if (runs == ULONG_MAX && errno == ERANGE) {
        fprintf(stderr, "Couldn't convert runs number from string '%s', it is out of range.\n",
                argv[2]);
        return -6;
    }

    struct timespec start_time, end_time, duration_time;
    if (clock_gettime(CLOCK_MONOTONIC, &start_time) != 0) {
        fprintf(stderr, "Couldn't get start time.\n");
        return -7;
    }

    fprintf(stderr, "Running benchmark with %lu runs and %u rounds\n", runs, rounds);

    for (unsigned long int i = 0; i < runs; ++i) {
        bench(rounds);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end_time) != 0) {
        fprintf(stderr, "Couldn't get end time.\n");
        return -8;
    }
    timespec_diff(&end_time, &start_time, &duration_time);
    double duration_seconds = timespec_to_seconds(&duration_time);
    fprintf(stderr, "KDF took %g seconds total or %g seconds per run.\n", duration_seconds,
            duration_seconds / (double)runs);
    return 0;
}
