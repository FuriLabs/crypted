/**
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2022 Eugenio Paolantonio (g7)
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <libcryptsetup.h>

#define PASSPHRASE_MAX 256

/* Path definitions */
#define RUN_DIR "/run"
#define HALIUM_MOUNTED_STAMP_NAME "halium-mounted"
#define HALIUM_MOUNTED_STAMP RUN_DIR "/" HALIUM_MOUNTED_STAMP_NAME
#define CRYPTED_HELPER_PIDFILE_NAME "crypted-helper.pid"
#define CRYPTED_HELPER_PIDFILE RUN_DIR "/" CRYPTED_HELPER_PIDFILE_NAME
#define CRYPTED_HELPER_FAILURE_NAME "crypted-helper-failed"
#define CRYPTED_HELPER_FAILURE RUN_DIR "/" CRYPTED_HELPER_FAILURE_NAME
#define BOOT_DONE_STAMP_NAME "boot-done"
#define BOOT_DONE_STAMP RUN_DIR "/" BOOT_DONE_STAMP_NAME

/* Error codes */
#define ERR_MISSING_ARGUMENTS 1
#define ERR_FAILED_TO_READ_PASSPHRASE 2
#define ERR_FAILED_TO_INIT 3
#define ERR_FAILED_TO_LOAD 4
#define ERR_FAILED_TO_ACTIVATE 5
#define ERR_FAILED_REENCRYPTION 6
#define ERR_FAILED_REENCRYPTION_RUN 7
#define ERR_FAILED_REGISTER_HANDLERS 8

/* Exit codes */
#define EXIT_UNABLE_TO_ACTIVATE 2

static int teardown = 0;

static void
handle_signal(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        fprintf(stderr, "Received signal %d, preparing for teardown\n", sig);
        teardown = 1;
    }
}

static int
register_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("Failed to register SIGINT handler");
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("Failed to register SIGTERM handler");
        return -1;
    }

    return 0;
}

static int
report_reencryption_status(uint64_t size, uint64_t offset, void *data)
{
    /* Silence warnings */
    (void) size;
    (void) offset;
    (void) data;

    /* TODO: Add a way to show progress */
    return teardown ? 1 : 0;
}

static int
needs_reencryption(struct crypt_device *cd)
{
    crypt_reencrypt_info status = crypt_reencrypt_status(cd, NULL);

    switch (status) {
        case CRYPT_REENCRYPT_NONE:
            return 0; /* No reencryption needed */
        case CRYPT_REENCRYPT_CLEAN:
            return 1; /* Reencryption in progress and clean */
        default:
            fprintf(stderr, "Reencryption status error on %s: %d\n",
                    crypt_get_device_name(cd), status);
            return 1; /* Assume we need to resume/handle it */
    }
}

static int
start_reencryption(struct crypt_device *cd, const char *name, const char *passphrase)
{
    int result;
    struct crypt_params_reencrypt params = {
        .resilience = "checksum",
        .hash = "sha256",
        .flags = CRYPT_REENCRYPT_RESUME_ONLY,
    };

    result = crypt_reencrypt_init_by_passphrase(cd, name,
                                                passphrase, strlen(passphrase),
                                                CRYPT_ANY_SLOT, 0,
                                                NULL, NULL, &params);
    if (result < 0) {
        fprintf(stderr, "Failed to initialize reencryption: %s\n", strerror(-result));
        return -1;
    }

    result = crypt_reencrypt_run(cd, report_reencryption_status, NULL);
    if (result < 0) {
        fprintf(stderr, "Failed to run reencryption: %s\n", strerror(-result));
        return -1;
    }

    return 0;
}

static int
activate(struct crypt_device *cd, const char *name, const char *passphrase)
{
    int result;

    result = crypt_load(cd, CRYPT_LUKS2, NULL);
    if (result < 0) {
        fprintf(stderr, "Failed to load LUKS device: %s\n", strerror(-result));
        return -1;
    }

    result = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT,
                                          passphrase, strlen(passphrase), 0);
    if (result < 0) {
        fprintf(stderr, "Failed to activate device: %s\n", strerror(-result));
        return -1;
    }

    return 0;
}

static int
write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("Failed to open file for writing");
        return -1;
    }

    fputs(content, f);
    fclose(f);
    return 0;
}

static int
file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

void
print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s --device <device> --header <header> [--rootmnt <rootmnt>] --name <n> [--strip-newlines]\n", program_name);
}

int
main(int argc, char *argv[])
{
    struct crypt_device *cd = NULL;
    char *device = NULL;
    char *header = NULL;
    char *rootmnt = NULL;
    char *target_name = NULL;
    char passphrase[PASSPHRASE_MAX] = {0};
    char pid_str[32] = {0};
    int strip_newlines = 0;
    int result;
    int exit_code = EXIT_SUCCESS;
    int run_fd = -1;
    int ch, i = 0;
    pid_t child;

    static struct option long_options[] = {
        {"device", required_argument, 0, 'd'},
        {"header", required_argument, 0, 'h'},
        {"rootmnt", required_argument, 0, 'r'},
        {"name", required_argument, 0, 'n'},
        {"strip-newlines", no_argument, 0, 's'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };

    while ((ch = getopt_long(argc, argv, "d:h:r:n:s", long_options, NULL)) != -1) {
        switch (ch) {
            case 'd':
                device = optarg;
                break;
            case 'h':
                header = optarg;
                break;
            case 'r':
                rootmnt = optarg;
                break;
            case 'n':
                target_name = optarg;
                break;
            case 's':
                strip_newlines = 1;
                break;
            case '?':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!device || !header || !target_name) {
        fprintf(stderr, "Missing required arguments\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Read passphrase from stdin */
    while ((ch = fgetc(stdin)) != EOF) {
        if (i < PASSPHRASE_MAX - 1 && (!strip_newlines || ch != '\n')) {
            passphrase[i++] = ch;
        } else if (i >= PASSPHRASE_MAX - 1) {
            fprintf(stderr, "Passphrase maximum length reached\n");
            break;
        }
    }

    if (i == 0) {
        fprintf(stderr, "Failed to read passphrase\n");
        return EXIT_UNABLE_TO_ACTIVATE; /* Unable to activate */
    }
    passphrase[i] = '\0';

    result = crypt_init_data_device(&cd, header, device);
    if (result < 0) {
        fprintf(stderr, "Failed to initialize cryptsetup: %s\n", strerror(-result));
        return EXIT_FAILURE;
    }

    /* Activate the device */
    if (activate(cd, target_name, passphrase) < 0) {
        exit_code = EXIT_UNABLE_TO_ACTIVATE; /* Unable to activate */
        goto cleanup;
    }

    /* Check if reencryption is needed */
    if (!needs_reencryption(cd)) {
        fprintf(stderr, "Device %s is already fully encrypted or doesn't need reencryption\n", target_name);
        goto cleanup;
    }

    /* Continue by starting the re-encryption process. */
    if ((run_fd = open(RUN_DIR, O_DIRECTORY)) == -1) {
        perror("Failed to open run directory");
        goto cleanup;
    }

    child = fork();
    if (child == -1) {
        perror("Failed to fork process");
        goto cleanup;
    } else if (child == 0) {
        /* Ensure systemd doesn't kill us before running switch_root: https://systemd.io/ROOT_STORAGE_DAEMONS/ */
        if (argv[0])
            argv[0][0] = '@';

        /* Register signal handlers */
        if (register_signals() < 0)
            exit(EXIT_FAILURE);

        /* Wait for the move to happen if rootmnt has been specified */
        if (rootmnt) {
            while (!teardown && !file_exists(HALIUM_MOUNTED_STAMP)) {
                fprintf(stderr, "Waiting for root move stamp...\n");
                sleep(1);
            }

            if (teardown)
                goto child_cleanup;

            /* If we're here, the mounted stamp has been touched - so we can chroot to the new root mountpoint */
            if (chroot(rootmnt) < 0) {
                perror("Failed to chroot");
                goto child_cleanup;
            }

            /* ..and finally remove the stamp file */
            if (unlinkat(run_fd, HALIUM_MOUNTED_STAMP_NAME, 0) == -1)
                perror("Failed to remove halium mounted stamp");
        }

        /* ..and finally remove the stamp file */
        while (!teardown && !file_exists(BOOT_DONE_STAMP)) {
            fprintf(stderr, "Waiting for boot completion...\n");
            sleep(10);
        }

        if (teardown)
            goto child_cleanup;

        /* Start reencryption */
        if (start_reencryption(cd, target_name, passphrase) < 0) {
            write_file(CRYPTED_HELPER_FAILURE, "Failed to run reencryption");
            goto child_cleanup;
        }

        fprintf(stderr, "Reencryption completed successfully!\n");
    child_cleanup:
        /* Cleanup in child process */
        if (file_exists(CRYPTED_HELPER_PIDFILE)) {
            /* Unlink pid file */
            if (unlinkat(run_fd, CRYPTED_HELPER_PIDFILE_NAME, 0) == -1)
                perror("Failed to remove PID file");
        }

        if (cd)
            crypt_free(cd);
        if (run_fd != -1)
            close(run_fd);

        exit(exit_code);
    } else {
        /* Write the child pid to the pidfile */
        snprintf(pid_str, sizeof(pid_str), "%d", child);
        if (write_file(CRYPTED_HELPER_PIDFILE, pid_str) < 0)
            fprintf(stderr, "Failed to write PID file\n");
    }
cleanup:
    if (cd)
        crypt_free(cd);
    if (run_fd != -1)
        close(run_fd);

    return exit_code;
}
