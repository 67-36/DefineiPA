#ifndef SignTool_Bridging_Header_h
#define SignTool_Bridging_Header_h

#include <zlib.h>

/// Decompress raw DEFLATE data (ZIP method 8).
/// Returns Z_OK on success, negative on error.
/// out_len receives the number of bytes written to dst.
static inline int signtool_inflate_raw(
    const unsigned char * __nonnull src, unsigned int src_len,
    unsigned char       * __nonnull dst, unsigned int dst_len,
    unsigned int        * __nonnull out_len)
{
    z_stream stream;
    stream.zalloc   = Z_NULL;
    stream.zfree    = Z_NULL;
    stream.opaque   = Z_NULL;
    stream.next_in  = (z_const Bytef *)src;
    stream.avail_in = src_len;
    stream.next_out = (Bytef *)dst;
    stream.avail_out = dst_len;

    /* wbits = -MAX_WBITS  →  raw DEFLATE (no zlib/gzip header) */
    int ret = inflateInit2_(&stream, -MAX_WBITS, ZLIB_VERSION,
                             (int)sizeof(z_stream));
    if (ret != Z_OK) { *out_len = 0; return ret; }

    ret = inflate(&stream, Z_FINISH);
    *out_len = (unsigned int)stream.total_out;
    inflateEnd(&stream);

    return (ret == Z_STREAM_END) ? Z_OK : ret;
}

#endif /* SignTool_Bridging_Header_h */
