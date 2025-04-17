#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT, NF_DROP */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define HOST_KEYWORD "Host: "

char *block_host = NULL;

// HTTP에서 Host 필드 파싱
int check_http_host(unsigned char *data, int size) {
    if (size <= 0) return 0;

    struct iphdr *ip = (struct iphdr *)data;
    if (ip->protocol != IPPROTO_TCP) return 0;

    int ip_header_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(data + ip_header_len);
    int tcp_header_len = tcp->doff * 4;

    unsigned char *payload = data + ip_header_len + tcp_header_len;
    int payload_len = size - ip_header_len - tcp_header_len;

    if (payload_len <= 0) return 0;


    if (strncmp((char *)payload, "GET", 3) != 0 &&
        strncmp((char *)payload, "POST", 4) != 0 &&
        strncmp((char *)payload, "HEAD", 4) != 0)
        return 0;

    char *host_pos = memmem(payload, payload_len, HOST_KEYWORD, strlen(HOST_KEYWORD));

    if (!host_pos) return 0;

    host_pos += strlen(HOST_KEYWORD);
    char *end = strchr(host_pos, '\r');
    if (!end) return 0;

    int host_len = end - host_pos;
    char host_value[256] = {0};
    strncpy(host_value, host_pos, host_len);
    host_value[host_len] = '\0';

    printf("Detected Host: %s\n", host_value);

    if (strcmp(host_value, block_host) == 0) {
        printf("Blocked Host matched: %s\n", host_value);
        return 1;
    }

    return 0;
}

static u_int32_t print_pkt(struct nfq_data *tb, unsigned char **payload_data, int *payload_len) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    u_int32_t id = 0;

    if (ph)
        id = ntohl(ph->packet_id);

    *payload_len = nfq_get_payload(tb, payload_data);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *pkt_data = NULL;
    int len = 0;
    u_int32_t id = print_pkt(nfa, &pkt_data, &len);

    int drop = check_http_host(pkt_data, len);
    if (drop) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    } else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "syntax : netfilter-test <host>\n");
        fprintf(stderr, "sample : netfilter-test test.gilgil.net\n");
        exit(1);
    }

    block_host = argv[1];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

