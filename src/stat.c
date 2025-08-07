#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

statistics_t statistics_data;

void stat_print(FILE *stat_fd)
{
    if (ftruncate(fileno(stat_fd), 0) != 0) {
        return;
    }

    fseek(stat_fd, 0, SEEK_SET);

    fprintf(stat_fd, "Statistics ");

    struct tm *tm_struct = localtime(&statistics_data.stat_start);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm_struct->tm_mday, tm_struct->tm_mon + 1,
            tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

    fprintf(stat_fd, " - ");

    time_t now = time(NULL);
    tm_struct = localtime(&now);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm_struct->tm_mday, tm_struct->tm_mon + 1,
            tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "DNS packets processed: %d\n", statistics_data.processed_count);
    fprintf(stat_fd, "DNS parsing errors   : %d\n", statistics_data.request_parsing_error);
    fprintf(stat_fd, "In route table:\n");
    for (int i = 0; i < gateways_count; i++) {
        fprintf(stat_fd, "    Route %d          : %d\n", i + 1, statistics_data.in_route_table[i]);
    }

#ifdef TUN_MODE
    double nat_sended_to_dev_size_gb = statistics_data.nat_sended_to_dev_size / 1024 / 1024 / 1024;
    fprintf(stat_fd, "NAT sended to internet        : %d ptks\n",
            statistics_data.nat_sended_to_dev);
    fprintf(stat_fd, "NAT sended to internet size   : %lf GB\n", nat_sended_to_dev_size_gb);

    fprintf(stat_fd, "\n");

    double nat_sended_to_client_size_gb =
        statistics_data.nat_sended_to_client_size / 1024 / 1024 / 1024;
    fprintf(stat_fd, "NAT sended to client          : %d ptks\n",
            statistics_data.nat_sended_to_client);
    fprintf(stat_fd, "NAT sended to client size     : %lf GB\n", nat_sended_to_client_size_gb);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "NAT sended to internet errors : %d ptks\n",
            statistics_data.nat_sended_to_dev_error);
    fprintf(stat_fd, "NAT sended to client errors   : %d ptks\n",
            statistics_data.nat_sended_to_client_error);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "NAT records count             : %d\n", statistics_data.nat_records);
#endif

    fflush(stat_fd);
}
