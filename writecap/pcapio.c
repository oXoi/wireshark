/* pcapio.c
 * Our own private code for writing libpcap files when capturing.
 *
 * We have these because we want a way to open a stream for output given
 * only a file descriptor.  libpcap 0.9[.x] has "pcap_dump_fopen()", which
 * provides that, but
 *
 *      1) earlier versions of libpcap doesn't have it
 *
 * and
 *
 *      2) WinPcap/Npcap don't have it, because a file descriptor opened
 *         by code built for one version of the MSVC++ C library
 *         can't be used by library routines built for another version
 *         (e.g., threaded vs. unthreaded).
 *
 * Libpcap's pcap_dump() also doesn't return any error indications.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#include <glib.h>

#include <wsutil/epochs.h>
#include <wsutil/file_util.h>
#include <wsutil/ws_padding_to.h>

#include "pcapio.h"
#include <wiretap/file_wrappers.h>

typedef void* WFILE_T;

struct pcapio_writer {
    WFILE_T fh;
    char* io_buffer;
    wtap_compression_type ctype;
};

/* Magic numbers in "libpcap" files.

   "libpcap" file records are written in the byte order of the host that
   writes them, and the reader is expected to fix this up.

   PCAP_MAGIC is the magic number, in host byte order; PCAP_SWAPPED_MAGIC
   is a byte-swapped version of that.

   PCAP_NSEC_MAGIC is for Ulf Lamping's modified "libpcap" format,
   which uses the same common file format as PCAP_MAGIC, but the
   timestamps are saved in nanosecond resolution instead of microseconds.
   PCAP_SWAPPED_NSEC_MAGIC is a byte-swapped version of that. */
#define PCAP_MAGIC                      0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC              0xd4c3b2a1
#define PCAP_NSEC_MAGIC                 0xa1b23c4d
#define PCAP_SWAPPED_NSEC_MAGIC         0x4d3cb2a1

/* "libpcap" file header. */
struct pcap_hdr {
    uint32_t magic;          /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds (nsecs for PCAP_NSEC_MAGIC) */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

/* Magic numbers in ".pcapng" files.
 *
 * .pcapng file records are written in the byte order of the host that
 * writes them, and the reader is expected to fix this up.
 * PCAPNG_MAGIC is the magic number, in host byte order;
 * PCAPNG_SWAPPED_MAGIC is a byte-swapped version of that.
 */
#define PCAPNG_MAGIC         0x1A2B3C4D
#define PCAPNG_SWAPPED_MAGIC 0x4D3C2B1A

/* Currently we are only supporting the initial version of
   the file format. */
#define PCAPNG_MAJOR_VERSION 1
#define PCAPNG_MINOR_VERSION 0

/* Section Header Block without options and trailing Block Total Length */
struct shb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_length;
};
#define SECTION_HEADER_BLOCK_TYPE 0x0A0D0D0A

/* Interface Description Block without options and trailing Block Total Length */
struct idb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
};
#define INTERFACE_DESCRIPTION_BLOCK_TYPE 0x00000001

/* Interface Statistics Block without actual packet, options, and trailing
   Block Total Length */
struct isb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
};
#define INTERFACE_STATISTICS_BLOCK_TYPE 0x00000005

/* Enhanced Packet Block without actual packet, options, and trailing
   Block Total Length */
struct epb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
};
#define ENHANCED_PACKET_BLOCK_TYPE 0x00000006

struct ws_option_tlv {
    uint16_t type;
    uint16_t value_length;
};
#define OPT_ENDOFOPT      0
#define OPT_COMMENT       1
#define EPB_FLAGS         2
#define SHB_HARDWARE      2 /* currently not used */
#define SHB_OS            3
#define SHB_USERAPPL      4
#define IDB_NAME          2
#define IDB_DESCRIPTION   3
#define IDB_IF_SPEED      8
#define IDB_TSRESOL       9
#define IDB_FILTER       11
#define IDB_OS           12
#define IDB_HARDWARE     15
#define ISB_STARTTIME     2
#define ISB_ENDTIME       3
#define ISB_IFRECV        4
#define ISB_IFDROP        5
#define ISB_FILTERACCEPT  6
#define ISB_OSDROP        7
#define ISB_USRDELIV      8
#define ADD_PADDING(x) ((((x) + 3) >> 2) << 2)

static WFILE_T
writecap_file_open(pcapio_writer* pfile, const char *filename)
{
    WFILE_T fh;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WTAP_GZIP_COMPRESSED:
            return gzwfile_open(filename);
#endif /* defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG) */
#ifdef HAVE_LZ4FRAME_H
        case WTAP_LZ4_COMPRESSED:
            return lz4wfile_open(filename);
#endif /* HAVE_LZ4FRAME_H */
        default:
            fh = ws_fopen(filename, "wb");
            /* Increase the size of the IO buffer if uncompressed.
             * Compression has its own buffer that reduces writes.
             */
            if (fh != NULL) {
                size_t buffsize = IO_BUF_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
                ws_statb64 statb;

                if (ws_stat64(filename, &statb) == 0) {
                    if (statb.st_blksize > IO_BUF_SIZE) {
                        buffsize = statb.st_blksize;
                    }
                }
#endif
                pfile->io_buffer = (char *)g_malloc(buffsize);
                setvbuf(fh, pfile->io_buffer, _IOFBF, buffsize);
                //ws_debug("buffsize %zu", buffsize);
            }
            return fh;
    }
}

static WFILE_T
writecap_file_fdopen(pcapio_writer* pfile, int fd)
{
    WFILE_T fh;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WTAP_GZIP_COMPRESSED:
            return gzwfile_fdopen(fd);
#endif /* defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG) */
#ifdef HAVE_LZ4FRAME_H
        case WTAP_LZ4_COMPRESSED:
            return lz4wfile_fdopen(fd);
#endif /* HAVE_LZ4FRAME_H */
        default:
            fh = ws_fdopen(fd, "wb");
            /* Increase the size of the IO buffer if uncompressed.
             * Compression has its own buffer that reduces writes.
             */
            if (fh != NULL) {
                size_t buffsize = IO_BUF_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
                ws_statb64 statb;

                if (ws_fstat64(fd, &statb) == 0) {
                    if (statb.st_blksize > IO_BUF_SIZE) {
                        buffsize = statb.st_blksize;
                    }
                }
#endif
                pfile->io_buffer = (char *)g_malloc(buffsize);
                setvbuf(fh, pfile->io_buffer, _IOFBF, buffsize);
                //ws_debug("buffsize %zu", buffsize);
            }
            return fh;
    }
}

pcapio_writer*
writecap_fopen(const char *filename, wtap_compression_type ctype, int *err)
{
    pcapio_writer* pfile;
    *err = 0;

    pfile = g_new0(struct pcapio_writer, 1);
    if (pfile == NULL) {
        *err = errno;
        return NULL;
    }
    pfile->ctype = ctype;
    errno = WTAP_ERR_CANT_OPEN;
    void* fh = writecap_file_open(pfile, filename);
    if (fh == NULL) {
        *err = errno;
	g_free(pfile);
	return NULL;
    }

    pfile->fh = fh;
    return pfile;
}

pcapio_writer*
writecap_fdopen(int fd, wtap_compression_type ctype, int *err)
{
    pcapio_writer* pfile;
    *err = 0;

    pfile = g_new0(struct pcapio_writer, 1);
    if (pfile == NULL) {
        *err = errno;
        return NULL;
    }
    pfile->ctype = ctype;
    errno = WTAP_ERR_CANT_OPEN;
    WFILE_T fh = writecap_file_fdopen(pfile, fd);
    if (fh == NULL) {
        *err = errno;
        g_free(pfile);
        return NULL;
    }

    pfile->fh = fh;
    return pfile;
}

pcapio_writer*
writecap_open_stdout(wtap_compression_type ctype, int *err)
{
    int new_fd;
    pcapio_writer* pfile;

    new_fd = ws_dup(1);
    if (new_fd == -1) {
        *err = errno;
        return NULL;
    }
#ifdef _WIN32
    /*
     * Put the new descriptor into binary mode.
     *
     * XXX - even if the file format we're writing is a text
     * format?
     */
    if (_setmode(new_fd, O_BINARY) == -1) {
        /* "Should not happen" */
        *err = errno;
        ws_close(new_fd);
        return NULL;
    }
#endif

    pfile = writecap_fdopen(new_fd, ctype, err);
    if (pfile == NULL) {
        /* Failed; close the new fd */
        ws_close(new_fd);
        return NULL;
    }
    return pfile;
}

bool
writecap_flush(pcapio_writer* pfile, int *err)
{
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WTAP_GZIP_COMPRESSED:
            if (gzwfile_flush((GZWFILE_T)pfile->fh) == -1) {
                if (err) {
                    *err = gzwfile_geterr((GZWFILE_T)pfile->fh);
                }
                return false;
            }
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WTAP_LZ4_COMPRESSED:
            if (lz4wfile_flush((LZ4WFILE_T)pfile->fh) == -1) {
                if (err) {
                    *err = lz4wfile_geterr((LZ4WFILE_T)pfile->fh);
                }
                return false;
            }
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            if (fflush((FILE*)pfile->fh) == EOF) {
                if (err) {
                    *err = errno;
                }
                return false;
            }
    }
    return true;
}

bool
writecap_close(pcapio_writer* pfile, int *errp)
{
    int err = 0;

    errno = WTAP_ERR_CANT_CLOSE;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WTAP_GZIP_COMPRESSED:
            err = gzwfile_close(pfile->fh);
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WTAP_LZ4_COMPRESSED:
            err = lz4wfile_close(pfile->fh);
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            if (fclose(pfile->fh) == EOF) {
                err = errno;
            }
    }

    g_free(pfile->io_buffer);
    g_free(pfile);
    if (errp) {
        *errp = err;
    }
    return err == 0;
}

/* Write to capture file */
static bool
write_to_file(pcapio_writer* pfile, const uint8_t* data, size_t data_length,
              uint64_t *bytes_written, int *err)
{
    size_t nwritten;

    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WTAP_GZIP_COMPRESSED:
            nwritten = gzwfile_write(pfile->fh, data, (unsigned)data_length);
            /*
             * gzwfile_write() returns 0 on error.
             */
            if (nwritten == 0) {
                *err = gzwfile_geterr(pfile->fh);
                return false;
            }
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WTAP_LZ4_COMPRESSED:
            nwritten = lz4wfile_write(pfile->fh, data, data_length);
            /*
             * lz4wfile_write() returns 0 on error.
             */
            if (nwritten == 0) {
                *err = lz4wfile_geterr(pfile->fh);
                return false;
            }
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            nwritten = fwrite(data, data_length, 1, pfile->fh);
            if (nwritten != 1) {
                if (ferror(pfile->fh)) {
                    *err = errno;
                } else {
                    *err = WTAP_ERR_SHORT_WRITE;
                }
                return false;
            }
            break;
    }

    (*bytes_written) += data_length;
    return true;
}

/* Writing pcap files */

/* Write the file header to a dump file.
   Returns true on success, false on failure.
   Sets "*err" to an error code, or 0 for a short write, on failure*/
bool
libpcap_write_file_header(pcapio_writer* pfile, int linktype, int snaplen, bool ts_nsecs, uint64_t *bytes_written, int *err)
{
    struct pcap_hdr file_hdr;

    file_hdr.magic = ts_nsecs ? PCAP_NSEC_MAGIC : PCAP_MAGIC;
    /* current "libpcap" format is 2.4 */
    file_hdr.version_major = 2;
    file_hdr.version_minor = 4;
    file_hdr.thiszone = 0;  /* XXX - current offset? */
    file_hdr.sigfigs = 0;   /* unknown, but also apparently unused */
    file_hdr.snaplen = snaplen;
    file_hdr.network = linktype;

    return write_to_file(pfile, (const uint8_t*)&file_hdr, sizeof(file_hdr), bytes_written, err);
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
bool
libpcap_write_packet(pcapio_writer* pfile,
                     time_t sec, uint32_t usec,
                     uint32_t caplen, uint32_t len,
                     const uint8_t *pd,
                     uint64_t *bytes_written, int *err)
{
    struct pcaprec_hdr rec_hdr;

    rec_hdr.ts_sec = (uint32_t)sec; /* Y2.038K issue in pcap format.... */
    rec_hdr.ts_usec = usec;
    rec_hdr.incl_len = caplen;
    rec_hdr.orig_len = len;
    if (!write_to_file(pfile, (const uint8_t*)&rec_hdr, sizeof(rec_hdr), bytes_written, err))
        return false;

    return write_to_file(pfile, pd, caplen, bytes_written, err);
}

/* Writing pcapng files */

static uint32_t
pcapng_count_string_option(const char *option_value)
{
    if ((option_value != NULL) && (strlen(option_value) > 0) && (strlen(option_value) < UINT16_MAX)) {
        /* There's a value to write; get its length */
        return (uint32_t)(sizeof(struct ws_option_tlv) +
                         (uint16_t)ADD_PADDING(strlen(option_value)));
    }
    return 0; /* nothing to write */
}

static bool
pcapng_write_string_option(pcapio_writer* pfile,
                           uint16_t option_type, const char *option_value,
                           uint64_t *bytes_written, int *err)
{
    size_t option_value_length;
    struct ws_option_tlv option;
    const uint32_t padding = 0;
    unsigned option_padding_length;

    if (option_value == NULL)
        return true; /* nothing to write */
    option_value_length = strlen(option_value);
    if ((option_value_length > 0) && (option_value_length < UINT16_MAX)) {
        /* something to write */
        option.type = option_type;
        option.value_length = (uint16_t)option_value_length;

        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)option_value, (int) option_value_length, bytes_written, err))
            return false;

        option_padding_length = WS_PADDING_TO_4(option_value_length);
        if (option_padding_length != 0) {
            if (!write_to_file(pfile, (const uint8_t*)&padding, option_padding_length, bytes_written, err))
                return false;
        }
    }
    return true;
}

/* Write a pre-formatted pcapng block directly to the output file */
bool
pcapng_write_block(pcapio_writer* pfile,
                   const uint8_t *data,
                   uint32_t length,
                   uint64_t *bytes_written,
                   int *err)
{
    uint32_t block_length, end_length;
    /* Check
     * - length and data are aligned to 4 bytes
     * - block_total_length field is the same at the start and end of the block
     *
     * The block_total_length is not checked against the provided length but
     * getting the trailing block_total_length from the length argument gives
     * us an implicit check of correctness without needing to do an endian swap
     */
    if (((length & 3) != 0) || (((intptr_t)data & 3) != 0)) {
        *err = EINVAL;
        return false;
    }
    block_length = *(const uint32_t *) (data+sizeof(uint32_t));
    end_length = *(const uint32_t *) (data+length-sizeof(uint32_t));
    if (block_length != end_length) {
        *err = EBADMSG;
        return false;
    }
    return write_to_file(pfile, data, length, bytes_written, err);
}

bool
pcapng_write_section_header_block(pcapio_writer* pfile,
                                  GPtrArray *comments,
                                  const char *hw,
                                  const char *os,
                                  const char *appname,
                                  uint64_t section_length,
                                  uint64_t *bytes_written,
                                  int *err)
{
    struct shb shb;
    struct ws_option_tlv option;
    uint32_t block_total_length;
    uint32_t options_length;

    /* Size of base header */
    block_total_length = sizeof(struct shb) + sizeof(uint32_t);
    options_length = 0;
    if (comments != NULL) {
        for (unsigned i = 0; i < comments->len; i++) {
            options_length += pcapng_count_string_option((char *)g_ptr_array_index(comments, i));
        }
    }
    options_length += pcapng_count_string_option(hw);
    options_length += pcapng_count_string_option(os);
    options_length += pcapng_count_string_option(appname);
    /* If we have options add size of end-of-options */
    if (options_length != 0) {
        options_length += (uint32_t)sizeof(struct ws_option_tlv);
    }
    block_total_length += options_length;

    /* write shb header */
    shb.block_type = SECTION_HEADER_BLOCK_TYPE;
    shb.block_total_length = block_total_length;
    shb.byte_order_magic = PCAPNG_MAGIC;
    shb.major_version = PCAPNG_MAJOR_VERSION;
    shb.minor_version = PCAPNG_MINOR_VERSION;
    shb.section_length = section_length;

    if (!write_to_file(pfile, (const uint8_t*)&shb, sizeof(struct shb), bytes_written, err))
        return false;

    if (comments != NULL) {
        for (unsigned i = 0; i < comments->len; i++) {
            if (!pcapng_write_string_option(pfile, OPT_COMMENT,
                                            (char *)g_ptr_array_index(comments, i),
                                            bytes_written, err))
                return false;
        }
    }
    if (!pcapng_write_string_option(pfile, SHB_HARDWARE, hw,
                                    bytes_written, err))
        return false;
    if (!pcapng_write_string_option(pfile, SHB_OS, os,
                                    bytes_written, err))
        return false;
    if (!pcapng_write_string_option(pfile, SHB_USERAPPL, appname,
                                    bytes_written, err))
        return false;
    if (options_length != 0) {
        /* write end of options */
        option.type = OPT_ENDOFOPT;
        option.value_length = 0;
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;
    }

    /* write the trailing block total length */
    return write_to_file(pfile, (const uint8_t*)&block_total_length, sizeof(uint32_t), bytes_written, err);
}

bool
pcapng_write_interface_description_block(pcapio_writer* pfile,
                                         const char *comment,  /* OPT_COMMENT        1 */
                                         const char *name,     /* IDB_NAME           2 */
                                         const char *descr,    /* IDB_DESCRIPTION    3 */
                                         const char *filter,   /* IDB_FILTER        11 */
                                         const char *os,       /* IDB_OS            12 */
                                         const char *hardware, /* IDB_HARDWARE      15 */
                                         int link_type,
                                         int snap_len,
                                         uint64_t *bytes_written,
                                         uint64_t if_speed,     /* IDB_IF_SPEED       8 */
                                         uint8_t tsresol,       /* IDB_TSRESOL        9 */
                                         int *err)
{
    struct idb idb;
    struct ws_option_tlv option;
    uint32_t block_total_length;
    uint32_t options_length;
    const uint32_t padding = 0;
    unsigned option_padding_length;

    block_total_length = (uint32_t)(sizeof(struct idb) + sizeof(uint32_t));
    options_length = 0;
    /* 01 - OPT_COMMENT */
    options_length += pcapng_count_string_option(comment);

    /* 02 - IDB_NAME */
    options_length += pcapng_count_string_option(name);

    /* 03 - IDB_DESCRIPTION */
    options_length += pcapng_count_string_option(descr);

    /* 08 - IDB_IF_SPEED */
    if (if_speed != 0) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint64_t));
    }

    /* 09 - IDB_TSRESOL */
    if (tsresol != 0) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(struct ws_option_tlv));
    }

    /* 11 - IDB_FILTER */
    if ((filter != NULL) && (strlen(filter) > 0) && (strlen(filter) < UINT16_MAX - 1)) {
        /* No, this isn't a string, it has an extra type byte */
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    (uint16_t)(ADD_PADDING(strlen(filter)+ 1)));
    }

    /* 12 - IDB_OS */
    options_length += pcapng_count_string_option(os);

    /* 15 - IDB_HARDWARE */
    options_length += pcapng_count_string_option(hardware);

    /* If we have options add size of end-of-options */
    if (options_length != 0) {
        options_length += (uint32_t)sizeof(struct ws_option_tlv);
    }
    block_total_length += options_length;

    /* write block header */
    idb.block_type = INTERFACE_DESCRIPTION_BLOCK_TYPE;
    idb.block_total_length = block_total_length;
    idb.link_type = link_type;
    idb.reserved = 0;
    idb.snap_len = snap_len;
    if (!write_to_file(pfile, (const uint8_t*)&idb, sizeof(struct idb), bytes_written, err))
        return false;

    /* 01 - OPT_COMMENT - write comment string if applicable */
    if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                    bytes_written, err))
        return false;

    /* 02 - IDB_NAME - write interface name string if applicable */
    if (!pcapng_write_string_option(pfile, IDB_NAME, name,
                                    bytes_written, err))
        return false;

    /* 03 - IDB_DESCRIPTION */
    /* write interface description string if applicable */
    if (!pcapng_write_string_option(pfile, IDB_DESCRIPTION, descr,
                                    bytes_written, err))
        return false;

    /* 08 - IDB_IF_SPEED */
    if (if_speed != 0) {
        option.type = IDB_IF_SPEED;
        option.value_length = sizeof(uint64_t);

        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&if_speed, sizeof(uint64_t), bytes_written, err))
            return false;
    }

    /* 09 - IDB_TSRESOL */
    if (tsresol != 0) {
        option.type = IDB_TSRESOL;
        option.value_length = sizeof(uint8_t);

        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&tsresol, sizeof(uint8_t), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&padding, 3, bytes_written, err))
            return false;
    }

    /* 11 - IDB_FILTER - write filter string if applicable
     * We write out the libpcap filter expression, not the
     * generated BPF code.
     */
    if ((filter != NULL) && (strlen(filter) > 0) && (strlen(filter) < UINT16_MAX - 1)) {
        option.type = IDB_FILTER;
        option.value_length = (uint16_t)(strlen(filter) + 1 );
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        /* The first byte of the Option Data keeps a code of the filter used, 0 = libpcap filter string */
        if (!write_to_file(pfile, (const uint8_t*)&padding, 1, bytes_written, err))
            return false;
        if (!write_to_file(pfile, (const uint8_t*)filter, (int) strlen(filter), bytes_written, err))
            return false;
        option_padding_length = WS_PADDING_TO_4(strlen(filter) + 1);
        if (option_padding_length != 0) {
            if (!write_to_file(pfile, (const uint8_t*)&padding, option_padding_length, bytes_written, err))
                return false;
        }
    }

    /* 12 - IDB_OS - write os string if applicable */
    if (!pcapng_write_string_option(pfile, IDB_OS, os,
                                    bytes_written, err))
        return false;

    /* 15 - IDB_HARDWARE - write hardware string if applicable */
    if (!pcapng_write_string_option(pfile, IDB_HARDWARE, hardware,
                                    bytes_written, err))
        return false;

    if (options_length != 0) {
        /* write end of options */
        option.type = OPT_ENDOFOPT;
        option.value_length = 0;
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;
    }

    /* write the trailing Block Total Length */
    return write_to_file(pfile, (const uint8_t*)&block_total_length, sizeof(uint32_t), bytes_written, err);
}

/* Write a record for a packet to a dump file.
   Returns true on success, false on failure. */
bool
pcapng_write_enhanced_packet_block(pcapio_writer* pfile,
                                   const char *comment,
                                   time_t sec, uint32_t usec,
                                   uint32_t caplen, uint32_t len,
                                   uint32_t interface_id,
                                   unsigned ts_mul,
                                   const uint8_t *pd,
                                   uint32_t flags,
                                   uint64_t *bytes_written,
                                   int *err)
{
    struct epb epb;
    struct ws_option_tlv option;
    uint32_t block_total_length;
    uint64_t timestamp;
    uint32_t options_length;
    const uint32_t padding = 0;
    uint8_t buff[8];
    uint8_t i;
    uint8_t pad_len;

    block_total_length = (uint32_t)(sizeof(struct epb) +
                                    ADD_PADDING(caplen) +
                                    sizeof(uint32_t));
    options_length = 0;
    options_length += pcapng_count_string_option(comment);
    if (flags != 0) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint32_t));
    }
    /* If we have options add size of end-of-options */
    if (options_length != 0) {
        options_length += (uint32_t)sizeof(struct ws_option_tlv);
    }
    block_total_length += options_length;
    timestamp = (uint64_t)sec * ts_mul + (uint64_t)usec;
    epb.block_type = ENHANCED_PACKET_BLOCK_TYPE;
    epb.block_total_length = block_total_length;
    epb.interface_id = interface_id;
    epb.timestamp_high = (uint32_t)((timestamp>>32) & 0xffffffff);
    epb.timestamp_low = (uint32_t)(timestamp & 0xffffffff);
    epb.captured_len = caplen;
    epb.packet_len = len;
    if (!write_to_file(pfile, (const uint8_t*)&epb, sizeof(struct epb), bytes_written, err))
        return false;
    if (!write_to_file(pfile, pd, caplen, bytes_written, err))
        return false;
    /* Use more efficient write in case of no "extras" */
    pad_len = WS_PADDING_TO_4(caplen);
    /*
     * If we have no options to write, just write out the padding and
     * the block total length with one fwrite() call.
     */
    if(!comment && flags == 0 && options_length==0){
        /* Put padding in the buffer */
        for (i = 0; i < pad_len; i++) {
            buff[i] = 0;
        }
        /* Write the total length */
        memcpy(&buff[i], &block_total_length, sizeof(uint32_t));
        i += sizeof(uint32_t);
        return write_to_file(pfile, (const uint8_t*)&buff, i, bytes_written, err);
    }
    if (pad_len) {
        if (!write_to_file(pfile, (const uint8_t*)&padding, pad_len, bytes_written, err))
            return false;
    }
    if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                    bytes_written, err))
        return false;
    if (flags != 0) {
        option.type = EPB_FLAGS;
        option.value_length = sizeof(uint32_t);
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;
        if (!write_to_file(pfile, (const uint8_t*)&flags, sizeof(uint32_t), bytes_written, err))
            return false;
    }
    if (options_length != 0) {
        /* write end of options */
        option.type = OPT_ENDOFOPT;
        option.value_length = 0;
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;
    }

    return write_to_file(pfile, (const uint8_t*)&block_total_length, sizeof(uint32_t), bytes_written, err);
}

bool
pcapng_write_interface_statistics_block(pcapio_writer* pfile,
                                        uint32_t interface_id,
                                        uint64_t *bytes_written,
                                        const char *comment,    /* OPT_COMMENT           1 */
                                        uint64_t isb_starttime, /* ISB_STARTTIME         2 */
                                        uint64_t isb_endtime,   /* ISB_ENDTIME           3 */
                                        uint64_t isb_ifrecv,    /* ISB_IFRECV            4 */
                                        uint64_t isb_ifdrop,    /* ISB_IFDROP            5 */
                                        int *err)
{
    struct isb isb;
#ifdef _WIN32
    FILETIME now;
#else
    struct timeval now;
#endif
    struct ws_option_tlv option;
    uint32_t block_total_length;
    uint32_t options_length;
    uint64_t timestamp;

#ifdef _WIN32
    /*
     * Current time, represented as 100-nanosecond intervals since
     * January 1, 1601, 00:00:00 UTC.
     *
     * I think DWORD might be signed, so cast both parts of "now"
     * to uint32_t so that the sign bit doesn't get treated specially.
     *
     * Windows 8 provides GetSystemTimePreciseAsFileTime which we
     * might want to use instead.
     */
    GetSystemTimeAsFileTime(&now);
    timestamp = (((uint64_t)(uint32_t)now.dwHighDateTime) << 32) +
                (uint32_t)now.dwLowDateTime;

    /*
     * Convert to same thing but as 1-microsecond, i.e. 1000-nanosecond,
     * intervals.
     */
    timestamp /= 10;

    /*
     * Subtract difference, in microseconds, between January 1, 1601
     * 00:00:00 UTC and January 1, 1970, 00:00:00 UTC.
     */
    timestamp -= EPOCH_DELTA_1601_01_01_00_00_00_UTC*1000000;
#else
    /*
     * Current time, represented as seconds and microseconds since
     * January 1, 1970, 00:00:00 UTC.
     */
    gettimeofday(&now, NULL);

    /*
     * Convert to delta in microseconds.
     */
    timestamp = (uint64_t)(now.tv_sec) * 1000000 +
                (uint64_t)(now.tv_usec);
#endif
    block_total_length = (uint32_t)(sizeof(struct isb) + sizeof(uint32_t));
    options_length = 0;
    if (isb_ifrecv != UINT64_MAX) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint64_t));
    }
    if (isb_ifdrop != UINT64_MAX) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint64_t));
    }
    /* OPT_COMMENT */
    options_length += pcapng_count_string_option(comment);
    if (isb_starttime !=0) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint64_t)); /* ISB_STARTTIME */
    }
    if (isb_endtime !=0) {
        options_length += (uint32_t)(sizeof(struct ws_option_tlv) +
                                    sizeof(uint64_t)); /* ISB_ENDTIME */
    }
    /* If we have options add size of end-of-options */
    if (options_length != 0) {
        options_length += (uint32_t)sizeof(struct ws_option_tlv);
    }
    block_total_length += options_length;

    isb.block_type = INTERFACE_STATISTICS_BLOCK_TYPE;
    isb.block_total_length = block_total_length;
    isb.interface_id = interface_id;
    isb.timestamp_high = (uint32_t)((timestamp>>32) & 0xffffffff);
    isb.timestamp_low = (uint32_t)(timestamp & 0xffffffff);
    if (!write_to_file(pfile, (const uint8_t*)&isb, sizeof(struct isb), bytes_written, err))
        return false;

    /* write comment string if applicable */
    if (!pcapng_write_string_option(pfile, OPT_COMMENT, comment,
                                    bytes_written, err))
        return false;

    if (isb_starttime !=0) {
        uint32_t high, low;

        option.type = ISB_STARTTIME;
        option.value_length = sizeof(uint64_t);
        high = (uint32_t)((isb_starttime>>32) & 0xffffffff);
        low = (uint32_t)(isb_starttime & 0xffffffff);
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&high, sizeof(uint32_t), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&low, sizeof(uint32_t), bytes_written, err))
            return false;
    }
    if (isb_endtime !=0) {
        uint32_t high, low;

        option.type = ISB_ENDTIME;
        option.value_length = sizeof(uint64_t);
        high = (uint32_t)((isb_endtime>>32) & 0xffffffff);
        low = (uint32_t)(isb_endtime & 0xffffffff);
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&high, sizeof(uint32_t), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&low, sizeof(uint32_t), bytes_written, err))
            return false;
    }
    if (isb_ifrecv != UINT64_MAX) {
        option.type = ISB_IFRECV;
        option.value_length = sizeof(uint64_t);
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&isb_ifrecv, sizeof(uint64_t), bytes_written, err))
            return false;
    }
    if (isb_ifdrop != UINT64_MAX) {
        option.type = ISB_IFDROP;
        option.value_length = sizeof(uint64_t);
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;

        if (!write_to_file(pfile, (const uint8_t*)&isb_ifdrop, sizeof(uint64_t), bytes_written, err))
            return false;
    }
    if (options_length != 0) {
        /* write end of options */
        option.type = OPT_ENDOFOPT;
        option.value_length = 0;
        if (!write_to_file(pfile, (const uint8_t*)&option, sizeof(struct ws_option_tlv), bytes_written, err))
            return false;
    }

    return write_to_file(pfile, (const uint8_t*)&block_total_length, sizeof(uint32_t), bytes_written, err);
}
