/* A buffered log reset must not retain previously written bytes. */
#include "telemetry.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    telemetry_t telemetry = { 0 };
    char old_lines[2000];
    long new_end;
    struct stat st;
    char prefix[12] = { 0 };
    int ok = 0;

    telemetry.log_fp = tmpfile();
    if (telemetry.log_fp == NULL) {
        perror("tmpfile");
        return 1;
    }
    if (setvbuf(telemetry.log_fp, NULL, _IOFBF, 8192) != 0) {
        goto done;
    }
    memset(old_lines, 'Z', sizeof(old_lines));
    if (fwrite(old_lines, 1, sizeof(old_lines), telemetry.log_fp) != sizeof(old_lines)) {
        goto done;
    }

    /* The first reset runs with dirty, not-yet-flushed stdio output. */
    telemetry_log_header(&telemetry);
    if (fflush(telemetry.log_fp) != 0) {
        goto done;
    }
    new_end = ftell(telemetry.log_fp);
    if (new_end <= 0 || fstat(fileno(telemetry.log_fp), &st) != 0 || st.st_size != new_end) {
        goto done;
    }

    rewind(telemetry.log_fp);
    if (fread(prefix, 1, strlen("Reductions:"), telemetry.log_fp) != strlen("Reductions:") ||
        strcmp(prefix, "Reductions:") != 0) {
        goto done;
    }

    /* A second reset must remove the previous header plus buffered DNS logs. */
    if (fseek(telemetry.log_fp, 0, SEEK_END) != 0) {
        goto done;
    }
    memset(old_lines, 'Q', sizeof(old_lines));
    if (fwrite(old_lines, 1, sizeof(old_lines), telemetry.log_fp) != sizeof(old_lines)) {
        goto done;
    }
    telemetry_log_header(&telemetry);
    if (fflush(telemetry.log_fp) != 0 || ftell(telemetry.log_fp) != new_end ||
        fstat(fileno(telemetry.log_fp), &st) != 0 || st.st_size != new_end) {
        goto done;
    }

    puts("PASS: buffered telemetry log reset leaves no stale data");
    ok = 1;

done:
    telemetry_close(&telemetry);
    return ok ? 0 : 1;
}
