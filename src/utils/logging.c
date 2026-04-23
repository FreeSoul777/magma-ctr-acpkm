#include "logging.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/stat.h>
#endif

static FILE*        log_file     = NULL;
static const char*  log_filename = "magma.log";
static const size_t max_log_size = 1024 * 1024;

static void log_rotate(void)
{
    if (!log_file)
        return;

    fflush(log_file);
    fclose(log_file);

    struct stat st;
    if (stat(log_filename, &st) == 0 && (size_t)st.st_size > max_log_size)
    {
        unlink("magma.log.old");
        rename(log_filename, "magma.log.old");
    }

    log_file = fopen(log_filename, "a");
}

void log_init(void)
{
    if (log_file)
        return;

    log_file = fopen(log_filename, "a");
    if (!log_file)
        return;

    setvbuf(log_file, NULL, _IOLBF, 0);

    time_t now = time(NULL);
    char   time_buf[26];
    ctime_r(&now, time_buf);
    time_buf[strcspn(time_buf, "\n")] = '\0';
    fprintf(log_file, "\n=== MAGMA SESSION STARTED at %s ===\n", time_buf);
    fflush(log_file);
}

void log_write(const char* event, const char* details)
{
    if (!log_file)
    {
        log_init();
        if (!log_file)
            return;
    }

    time_t    now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);

    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(log_file, "[%s] %-12s: %s\n", time_buf, event, details);
    fflush(log_file);

    static int log_counter = 0;
    if (++log_counter >= 50)
    {
        log_counter = 0;
        log_rotate();
    }
}

void log_close(void)
{
    if (log_file)
    {
        time_t now = time(NULL);
        char   time_buf[26];
        ctime_r(&now, time_buf);
        time_buf[strcspn(time_buf, "\n")] = '\0';
        fprintf(log_file, "=== MAGMA SESSION ENDED at %s ===\n", time_buf);
        fclose(log_file);
        log_file = NULL;
    }
}
