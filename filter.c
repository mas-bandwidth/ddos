
#include <assert.h>
#include <memory.h>
#include <string.h>

#if !defined (LITTLE_ENDIAN ) && !defined(BIG_ENDIAN)

  #ifdef __BYTE_ORDER__
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      #define LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      #define BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define LITTLE_ENDIAN or BIG_ENDIAN.
    #endif // __BYTE_ORDER__

  // Detect with GLIBC's endian.h
  #elif defined(__GLIBC__)
    #include <endian.h>
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
      #define LITTLE_ENDIAN 1
    #elif (__BYTE_ORDER == __BIG_ENDIAN)
      #define BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define LITTLE_ENDIAN or BIG_ENDIAN.
    #endif // __BYTE_ORDER

  // Detect with _LITTLE_ENDIAN and _BIG_ENDIAN macro
  #elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
    #define LITTLE_ENDIAN 1
  #elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
    #define BIG_ENDIAN 1

  // Detect with architecture macros
  #elif    defined(__sparc)     || defined(__sparc__)                           \
        || defined(_POWER)      || defined(__powerpc__)                         \
        || defined(__ppc__)     || defined(__hpux)      || defined(__hppa)      \
        || defined(_MIPSEB)     || defined(_POWER)      || defined(__s390__)
    #define BIG_ENDIAN 1
  #elif    defined(__i386__)    || defined(__alpha__)   || defined(__ia64)      \
        || defined(__ia64__)    || defined(_M_IX86)     || defined(_M_IA64)     \
        || defined(_M_ALPHA)    || defined(__amd64)     || defined(__amd64__)   \
        || defined(_M_AMD64)    || defined(__x86_64)    || defined(__x86_64__)  \
        || defined(_M_X64)      || defined(__bfin__)
    #define LITTLE_ENDIAN 1
  #elif defined(_MSC_VER) && defined(_M_ARM)
    #define LITTLE_ENDIAN 1
  #else
    #error Unknown machine endianess detected. Please define LITTLE_ENDIAN or BIG_ENDIAN.
  #endif

#endif

#if !defined(BIG_ENDIAN)
#define BIG_ENDIAN 0
#endif // #if !defined(BIG_ENDIAN)

#if !defined(LITTLE_ENDIAN)
#define LITTLE_ENDIAN 0
#endif // #if !defined(LITTLE_ENDIAN)

typedef uint64_t fnv_t;

inline void fnv_init( fnv_t * fnv )
{
    *fnv = 0xCBF29CE484222325;
}

inline void fnv_write( fnv_t * fnv, const uint8_t * data, size_t size )
{
    for ( size_t i = 0; i < size; i++ )
    {
        (*fnv) ^= data[i];
        (*fnv) *= 0x00000100000001B3;
    }
}

inline uint64_t fnv_finalize( fnv_t * fnv )
{
    return *fnv;
}

inline uint64_t bswap( uint64_t value )
{
#ifdef __GNUC__
    return __builtin_bswap64( value );
#else // #ifdef __GNUC__
    value = ( value & 0x00000000FFFFFFFF ) << 32 | ( value & 0xFFFFFFFF00000000 ) >> 32;
    value = ( value & 0x0000FFFF0000FFFF ) << 16 | ( value & 0xFFFF0000FFFF0000 ) >> 16;
    value = ( value & 0x00FF00FF00FF00FF ) << 8  | ( value & 0xFF00FF00FF00FF00 ) >> 8;
    return value;
#endif // #ifdef __GNUC__
}

inline void generate_pittle( uint8_t * output, const uint8_t * from_address, const uint8_t * to_address, uint16_t packet_length )
{
    assert( output );
    assert( from_address );
    assert( to_address );
    assert( packet_length > 0 );
#if BIG_ENDIAN
    bswap( packet_length );
#endif // #if BIG_ENDIAN
    uint16_t sum = 0;
    for ( int i = 0; i < 4; ++i ) { sum += uint8_t(from_address[i]); }
    for ( int i = 0; i < 4; ++i ) { sum += uint8_t(to_address[i]); }
    const char * packet_length_data = (const char*) &packet_length;
    sum += uint8_t(packet_length_data[0]);
    sum += uint8_t(packet_length_data[1]);
#if BIG_ENDIAN
    bswap( sum );
#endif // #if BIG_ENDIAN
    const char * sum_data = (const char*) &sum;
    output[0] = 1 | ( uint8_t(sum_data[0]) ^ uint8_t(sum_data[1]) ^ 193 );
    output[1] = 1 | ( ( 255 - output[0] ) ^ 113 );
}

inline void generate_chonkle( uint8_t * output, const uint8_t * magic, const uint8_t * from_address, const uint8_t * to_address, uint16_t packet_length )
{
    assert( output );
    assert( magic );
    assert( from_address );
    assert( to_address );
    assert( packet_length > 0 );
#if BIG_ENDIAN
    bswap( packet_length );
#endif // #if BIG_ENDIAN
    fnv_t fnv;
    fnv_init( &fnv );
    fnv_write( &fnv, magic, 8 );
    fnv_write( &fnv, from_address, 4 );
    fnv_write( &fnv, to_address, 4 );
    fnv_write( &fnv, (const uint8_t*) &packet_length, 2 );
    uint64_t hash = fnv_finalize( &fnv );
#if BIG_ENDIAN
    bswap( hash );
#endif // #if BIG_ENDIAN
    const char * data = (const char*) &hash;
    output[0] = ( ( data[6] & 0xC0 ) >> 6 ) + 42;
    output[1] = ( data[3] & 0x1F ) + 200;
    output[2] = ( ( data[2] & 0xFC ) >> 2 ) + 5;
    output[3] = data[0];
    output[4] = ( data[2] & 0x03 ) + 78;
    output[5] = ( data[4] & 0x7F ) + 96;
    output[6] = ( ( data[1] & 0xFC ) >> 2 ) + 100;
    if ( ( data[7] & 1 ) == 0 ) { output[7] = 79; } else { output[7] = 7; }
    if ( ( data[4] & 0x80 ) == 0 ) { output[8] = 37; } else { output[8] = 83; }
    output[9] = ( data[5] & 0x07 ) + 124;
    output[10] = ( ( data[1] & 0xE0 ) >> 5 ) + 175;
    output[11] = ( data[6] & 0x3F ) + 33;
    const int value = ( data[1] & 0x03 );
    if ( value == 0 ) { output[12] = 97; } else if ( value == 1 ) { output[12] = 5; } else if ( value == 2 ) { output[12] = 43; } else { output[12] = 13; }
    output[13] = ( ( data[5] & 0xF8 ) >> 3 ) + 210;
    output[14] = ( ( data[7] & 0xFE ) >> 1 ) + 17;
}

inline bool basic_packet_filter( const uint8_t * data, uint16_t packet_length )
{
    if ( packet_length == 0 )
        return false;

    if ( data[0] == 0 ) // IMPORTANT: passthrough packet type
        return true;

    if ( packet_length < 18 )
        return false;

    if ( data[2] != ( 1 | ( ( 255 - data[1] ) ^ 113 ) ) )
        return false;

    if ( data[3] < 0x2A || data[3] > 0x2D )
        return false;

    if ( data[4] < 0xC8 || data[4] > 0xE7 )
        return false;

    if ( data[5] < 0x05 || data[5] > 0x44 )
        return false;

    if ( data[7] < 0x4E || data[7] > 0x51 )
        return false;

    if ( data[8] < 0x60 || data[8] > 0xDF )
        return false;

    if ( data[9] < 0x64 || data[9] > 0xE3 )
        return false;

    if ( data[10] != 0x07 && data[10] != 0x4F )
        return false;

    if ( data[11] != 0x25 && data[11] != 0x53 )
        return false;

    if ( data[12] < 0x7C || data[12] > 0x83 )
        return false;

    if ( data[13] < 0xAF || data[13] > 0xB6 )
        return false;

    if ( data[14] < 0x21 || data[14] > 0x60 )
        return false;

    if ( data[15] != 0x61 && data[15] != 0x05 && data[15] != 0x2B && data[15] != 0x0D )
        return false;

    if ( data[16] < 0xD2 || data[16] > 0xF1 )
        return false;

    if ( data[17] < 0x11 || data[17] > 0x90 )
        return false;

    return true;
}

inline bool advanced_packet_filter( const uint8_t * data, const uint8_t * magic, const uint8_t * from_address, const uint8_t * to_address, uint16_t packet_length )
{
    if ( data[0] == 0 ) // IMPORTANT: for passthrough packet type
        return true;

    if ( packet_length < 18 )
        return false;
    
    uint8_t a[2];
    uint8_t b[15];

    generate_pittle( a, from_address, to_address, packet_length );

    generate_chonkle( b, magic, from_address, to_address, packet_length );

    if ( memcmp( a, data + 1, 2 ) != 0 )
        return false;

    if ( memcmp( b, data + 3, 15 ) != 0 )
        return false;

    return true;
}
