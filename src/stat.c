#include "antiblock.h"
#include "config.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "domains_read.h"

statistics_t statistics_data;

void stat_print(FILE *stat_fd)
{
    if (ftruncate(fileno(stat_fd), 0) != 0) {
        return;
    }

    fseek(stat_fd, 0, SEEK_SET);

    fprintf(stat_fd, "Statistics ");

    struct tm *tm = localtime(&statistics_data.stat_start);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm->tm_mday, tm->tm_mon + 1,
            tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);

    fprintf(stat_fd, " - ");

    time_t now = time(NULL);
    tm = localtime(&now);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm->tm_mday, tm->tm_mon + 1,
            tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "DNS packets processed: %d\n", statistics_data.processed_count);
    fprintf(stat_fd, "DNS parsing errors   : %d\n", statistics_data.request_parsing_error);
    fprintf(stat_fd, "In route table:\n");
    for (int32_t i = 0; i < gateways_count; i++) {
        fprintf(stat_fd, "    Route %d          : %d\n", i + 1, statistics_data.in_route_table[i]);
    }

    fflush(stat_fd);
}
