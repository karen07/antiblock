#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

statistics_t stat;

void stat_print(void)
{
    ftruncate(fileno(stat_fd), 0);
    fseek(stat_fd, 0, SEEK_SET);

    fprintf(stat_fd, "Statistics ");

    struct tm *tm_struct = localtime(&stat.stat_start);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm_struct->tm_mday, tm_struct->tm_mon + 1,
            tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

    fprintf(stat_fd, " - ");

    time_t now = time(NULL);
    tm_struct = localtime(&now);
    fprintf(stat_fd, "%02d.%02d.%04d %02d:%02d:%02d", tm_struct->tm_mday, tm_struct->tm_mon + 1,
            tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "DNS sended to DNS             : %d\n", stat.sended_to_dns);
    fprintf(stat_fd, "DNS sended to client          : %d\n", stat.sended_to_client);

    fprintf(stat_fd, "\n");

    fprintf(stat_fd, "DNS sended to DNS errors      : %d\n", stat.sended_to_dns_error);
    fprintf(stat_fd, "DNS sended to client errors   : %d\n", stat.sended_to_client_error);
    fprintf(stat_fd, "DNS parsing errors            : %d\n", stat.request_parsing_error);

    fprintf(stat_fd, "\n");

    if (is_tun_name) {
        double nat_sended_to_dev_size_gb = stat.nat_sended_to_dev_size / 1024 / 1024 / 1024;
        fprintf(stat_fd, "NAT sended to internet        : %d ptks\n", stat.nat_sended_to_dev);
        fprintf(stat_fd, "NAT sended to internet size   : %lf GB\n", nat_sended_to_dev_size_gb);

        fprintf(stat_fd, "\n");

        double nat_sended_to_client_size_gb = stat.nat_sended_to_client_size / 1024 / 1024 / 1024;
        fprintf(stat_fd, "NAT sended to client          : %d ptks\n", stat.nat_sended_to_client);
        fprintf(stat_fd, "NAT sended to client size     : %lf GB\n", nat_sended_to_client_size_gb);

        fprintf(stat_fd, "\n");

        fprintf(stat_fd, "NAT sended to internet errors : %d ptks\n", stat.nat_sended_to_dev_error);
        fprintf(stat_fd, "NAT sended to client errors   : %d ptks\n",
                stat.nat_sended_to_client_error);

        fprintf(stat_fd, "\n");

        fprintf(stat_fd, "NAT records count             : %d\n", stat.nat_records);
    }

    fflush(stat_fd);
}
