/* Combine dump files, either by appending or by merging by timestamp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Mergecap written by Scott Renfro <scott@renfro.org> based on
 * editcap by Richard Sharpe and Guy Harris
 *
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include <wsutil/ws_getopt.h>

#include <string.h>

#include <wiretap/wtap.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/strnatcmp.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>
#include <ws_exit_codes.h>

#include <cli_main.h>
#include <wsutil/version_info.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wiretap/merge.h>

#include "ui/failure_message.h"

#define LONGOPT_COMPRESS                LONGOPT_BASE_APPLICATION+1

/*
 * Show the usage
 */
static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: mergecap [options] -w <outfile>|- <infile> [<infile> ...]\n");
    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -a                concatenate rather than merge files.\n");
    fprintf(output, "                    default is to merge based on frame timestamps.\n");
    fprintf(output, "  -s <snaplen>      truncate packets to <snaplen> bytes of data.\n");
    fprintf(output, "  -w <outfile>|-    set the output filename to <outfile> or '-' for stdout.\n");
    fprintf(output, "                    if the output filename has the .gz extension, it will be compressed to a gzip archive\n");
    fprintf(output, "  -F <capture type> set the output file type; default is pcapng.\n");
    fprintf(output, "                    an empty \"-F\" option will list the file types.\n");
    fprintf(output, "  -I <IDB merge mode> set the merge mode for Interface Description Blocks; default is 'all'.\n");
    fprintf(output, "                    an empty \"-I\" option will list the merge modes.\n");
    fprintf(output, "  --compress <type> compress the output file using the type compression format.\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h, --help        display this help and exit.\n");
    fprintf(output, "  -V                verbose output.\n");
    fprintf(output, "  -v, --version     print version information and exit.\n");
}

static void
list_capture_types(void) {
    GArray *writable_type_subtypes;

    fprintf(stderr, "mergecap: The available capture file types for the \"-F\" flag are:\n");
    writable_type_subtypes = wtap_get_writable_file_types_subtypes(FT_SORT_BY_NAME);
    for (unsigned i = 0; i < writable_type_subtypes->len; i++) {
        int ft = g_array_index(writable_type_subtypes, int, i);
        fprintf(stderr, "    %s - %s\n", wtap_file_type_subtype_name(ft),
                wtap_file_type_subtype_description(ft));
    }
    g_array_free(writable_type_subtypes, TRUE);
}

static void
list_idb_merge_modes(void) {
    int i;

    fprintf(stderr, "mergecap: The available IDB merge modes for the \"-I\" flag are:\n");
    for (i = 0; i < IDB_MERGE_MODE_MAX; i++) {
        fprintf(stderr, "    %s\n", merge_idb_merge_mode_to_string(i));
    }
}

static void
list_output_compression_types(void) {
    GSList *output_compression_types;

    fprintf(stderr, "mergecap: The available output compress type(s) for the \"--compress\" flag are:\n");
    output_compression_types = wtap_get_all_output_compression_type_names_list();
    for (GSList *compression_type = output_compression_types;
        compression_type != NULL;
        compression_type = g_slist_next(compression_type)) {
            fprintf(stderr, "   %s\n", (const char *)compression_type->data);
        }

    g_slist_free(output_compression_types);
}

static bool
merge_callback(merge_event event, int num,
        const merge_in_file_t in_files[], const unsigned in_file_count,
        void *data _U_)
{
    unsigned i;

    switch (event) {

        case MERGE_EVENT_INPUT_FILES_OPENED:
            for (i = 0; i < in_file_count; i++) {
                fprintf(stderr, "mergecap: %s is type %s.\n", in_files[i].filename,
                        wtap_file_type_subtype_description(wtap_file_type_subtype(in_files[i].wth)));
            }
            break;

        case MERGE_EVENT_FRAME_TYPE_SELECTED:
            /* for this event, num = frame_type */
            if (num == WTAP_ENCAP_PER_PACKET) {
                /*
                 * Find out why we had to choose WTAP_ENCAP_PER_PACKET.
                 */
                int first_frame_type, this_frame_type;

                first_frame_type = wtap_file_encap(in_files[0].wth);
                for (i = 1; i < in_file_count; i++) {
                    this_frame_type = wtap_file_encap(in_files[i].wth);
                    if (first_frame_type != this_frame_type) {
                        fprintf(stderr, "mergecap: multiple frame encapsulation types detected\n");
                        fprintf(stderr, "          defaulting to WTAP_ENCAP_PER_PACKET\n");
                        fprintf(stderr, "          %s had type %s (%s)\n",
                                in_files[0].filename,
                                wtap_encap_description(first_frame_type),
                                wtap_encap_name(first_frame_type));
                        fprintf(stderr, "          %s had type %s (%s)\n",
                                in_files[i].filename,
                                wtap_encap_description(this_frame_type),
                                wtap_encap_name(this_frame_type));
                        break;
                    }
                }
            }
            fprintf(stderr, "mergecap: selected frame_type %s (%s)\n",
                    wtap_encap_description(num),
                    wtap_encap_name(num));
            break;

        case MERGE_EVENT_READY_TO_MERGE:
            fprintf(stderr, "mergecap: ready to merge records\n");
            break;

        case MERGE_EVENT_RECORD_WAS_READ:
            /* for this event, num = count */
            fprintf(stderr, "Record: %d\n", num);
            break;

        case MERGE_EVENT_DONE:
            fprintf(stderr, "mergecap: merging complete\n");
            break;
    }

    /* false = do not stop merging */
    return false;
}

int
main(int argc, char *argv[])
{
    char               *configuration_init_error;
    int                 opt;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {"compress", ws_required_argument, NULL, LONGOPT_COMPRESS},
        LONGOPT_WSLOG
        {0, 0, 0, 0 }
    };
#define OPTSTRING "aF:hI:s:vVw:"
    static const char optstring[] = OPTSTRING;
    bool                  do_append        = false;
    bool                  verbose          = false;
    int                   in_file_count    = 0;
    uint32_t              snaplen          = 0;
    int                   file_type        = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    char                  *out_filename    = NULL;
    bool                  status           = true;
    idb_merge_mode        mode             = IDB_MERGE_MODE_MAX;
    wtap_compression_type compression_type = WTAP_UNKNOWN_COMPRESSION;
    merge_progress_callback_t cb;

    /* Set the program name. */
    g_set_prgname("mergecap");

    cmdarg_err_init(stderr_cmdarg_err, stderr_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init(vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, optstring, long_options, vcmdarg_err, WS_EXIT_INVALID_OPTION);

    ws_noisy("Finished log init and parsing command line log arguments");

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0]);
    if (configuration_init_error != NULL) {
        cmdarg_err(
                "Can't get pathname of directory containing the mergecap program: %s.",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    /* Initialize the version information. */
    ws_init_version_info("Mergecap", NULL, NULL);

    init_report_failure_message("mergecap");

    wtap_init(true);

    /* Process the options first */
    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {

        switch (opt) {
            case 'a':
                do_append = !do_append;
                break;

            case 'F':
                file_type = wtap_name_to_file_type_subtype(ws_optarg);
                if (file_type < 0) {
                    cmdarg_err("\"%s\" isn't a valid capture file type",
                               ws_optarg);
                    list_capture_types();
                    status = false;
                    goto clean_exit;
                }
                break;

            case 'h':
                show_help_header("Merge two or more capture files into one.");
                print_usage(stdout);
                goto clean_exit;
                break;

            case 'I':
                mode = merge_string_to_idb_merge_mode(ws_optarg);
                if (mode == IDB_MERGE_MODE_MAX) {
                    cmdarg_err("\"%s\" isn't a valid IDB merge mode",
                               ws_optarg);
                    list_idb_merge_modes();
                    status = false;
                    goto clean_exit;
                }
                break;

            case 's':
                if (!get_nonzero_uint32(ws_optarg, "snapshot length", &snaplen)) {
                    status = false;
                    goto clean_exit;
                }
                break;

            case 'V':
                verbose = true;
                break;

            case 'v':
                show_version();
                goto clean_exit;
                break;

            case 'w':
                out_filename = ws_optarg;
                break;

            case LONGOPT_COMPRESS:
                compression_type = wtap_name_to_compression_type(ws_optarg);
                if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
                    cmdarg_err("\"%s\" isn't a valid output compression mode",
                                ws_optarg);
                    list_output_compression_types();
                    goto clean_exit;
                }
                break;
            case '?':              /* Bad options if GNU getopt */
            default:
                /* wslog arguments are okay */
                if (ws_log_is_wslog_arg(opt))
                    break;

                switch(ws_optopt) {
                    case'F':
                        list_capture_types();
                        break;
                    case'I':
                        list_idb_merge_modes();
                        break;
                    case LONGOPT_COMPRESS:
                        list_output_compression_types();
                        break;
                    default:
                        print_usage(stderr);
                }
                status = false;
                goto clean_exit;
                break;
        }
    }

    /* Default to pcapng when writing. */
    if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN)
        file_type = wtap_pcapng_file_type_subtype();

    cb.callback_func = merge_callback;
    cb.data = NULL;

    /* check for proper args; at a minimum, must have an output
     * filename and one input file
     */
    in_file_count = argc - ws_optind;
    if (!out_filename) {
        cmdarg_err("an output filename must be set with -w");
        cmdarg_err_cont("run with -h for help");
        status = false;
        goto clean_exit;
    }
    if (in_file_count < 1) {
        cmdarg_err("No input files were specified");
        return 1;
    }

    if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
        /* An explicitly specified compression type overrides filename
         * magic. (Should we allow specifying "no" compression with, e.g.
         * a ".gz" extension?) */
        const char *sfx = strrchr(out_filename, '.');
        if (sfx) {
            compression_type = wtap_extension_to_compression_type(sfx + 1);
        }
    }

    if (compression_type == WTAP_UNKNOWN_COMPRESSION) {
        compression_type = WTAP_UNCOMPRESSED;
    }

    if (!wtap_can_write_compression_type(compression_type)) {
        cmdarg_err("Output files can't be written as %s",
                wtap_compression_type_description(compression_type));
        status = false;
        goto clean_exit;
    }

    if (compression_type != WTAP_UNCOMPRESSED && !wtap_dump_can_compress(file_type)) {
        cmdarg_err("The file format %s can't be written to output compressed format",
            wtap_file_type_subtype_name(file_type));
        status = false;
        goto clean_exit;
    }

    /*
     * Setting IDB merge mode must use a file format that supports
     * (and thus requires) interface ID and information blocks.
     */
    if (mode != IDB_MERGE_MODE_MAX &&
            wtap_file_type_subtype_supports_block(file_type, WTAP_BLOCK_IF_ID_AND_INFO) == BLOCK_NOT_SUPPORTED) {
        cmdarg_err("The IDB merge mode can only be used with an output format that identifies interfaces");
        status = false;
        goto clean_exit;
    }

    /* if they didn't set IDB merge mode, set it to our default */
    if (mode == IDB_MERGE_MODE_MAX) {
        mode = IDB_MERGE_MODE_ALL_SAME;
    }

    /* open the outfile */
    if (strcmp(out_filename, "-") == 0) {
        /* merge the files to the standard output */
        status = merge_files_to_stdout(file_type,
                (const char *const *) &argv[ws_optind],
                in_file_count, do_append, mode, snaplen,
                get_appname_and_version(),
                verbose ? &cb : NULL, compression_type);
    } else {
        /* merge the files to the outfile */
        status = merge_files(out_filename, file_type,
                (const char *const *) &argv[ws_optind], in_file_count,
                do_append, mode, snaplen, get_appname_and_version(),
                verbose ? &cb : NULL, compression_type);
    }

clean_exit:
    wtap_cleanup();
    free_progdirs();
    return status ? 0 : 2;
}
