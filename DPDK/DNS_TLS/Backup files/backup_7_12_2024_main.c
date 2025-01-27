/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <fcntl.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 100

#define IPV4_PROTO 2048
uint64_t total_pkts;

typedef struct
{
    rte_be32_t words[8];
} uint256_t;

typedef struct
{
    uint8_t bytes[3];
} uint24_t;

struct tls_hdr
{
    uint8_t type;
    uint16_t version;
    uint16_t len;
};

struct rte_tls_hdr
{
    uint8_t type;
    rte_be16_t version;
    rte_be16_t length;
} __rte_packed;

struct rte_tls_hello_hdr
{
    uint8_t type;
    uint24_t len;
    rte_be16_t version;
    uint256_t random;
} __rte_packed;

struct rte_tls_session_hdr
{
    uint8_t len;
} __rte_packed;

struct rte_tls_cipher_hdr
{
    uint16_t len;
} __rte_packed;

struct rte_tls_compression_hdr
{
    uint8_t len;
} __rte_packed;

struct rte_tls_ext_len_hdr
{
    uint16_t len;
} __rte_packed;

struct rte_tls_ext_hdr
{
    uint16_t type;
    uint16_t len;
} __rte_packed;

struct rte_ctls_ext_sni_hdr
{
    uint16_t sni_list_len;
    uint8_t type;
    uint16_t sni_len;
} __rte_packed;

struct rte_server_name
{
    uint16_t name;
} __rte_packed;

/* >8 End of launching function on lcore. */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    rte_eth_promiscuous_enable(port);

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));

        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    rxconf = dev_info.default_rxconf;

    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    return 0;
}

#define MAX_NAME_LENGTH 100
char **read_names_from_file(const char *filename, int *num_names);
char **read_names_from_file(const char *filename, int *num_names)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    char **names = NULL;
    *num_names = 0;
    char line[MAX_NAME_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Remove newline character if present
        line[strcspn(line, "\n")] = '\0';

        // Allocate memory for the new name
        char *new_name = malloc(strlen(line) + 1);
        if (new_name == NULL)
        {
            fprintf(stderr, "Memory allocation failed for name: %s\n", line);
            fclose(file);

            // Free all previously allocated names on error
            for (int i = 0; i < *num_names; i++)
            {
                free(names[i]);
            }
            free(names);

            return NULL;
        }

        // Copy the name into allocated memory
        strcpy(new_name, line);

        // Resize the names array to hold the new name
        char **temp = realloc(names, (*num_names + 1) * sizeof(char *));
        if (temp == NULL)
        {
            fprintf(stderr, "Memory reallocation failed\n");
            free(new_name);
            fclose(file);

            // Free all previously allocated names on error
            for (int i = 0; i < *num_names; i++)
            {
                free(names[i]);
            }
            free(names);

            return NULL;
        }
        names = temp;

        // Store the new name in the names array
        names[*num_names] = new_name;
        (*num_names)++;
    }

    fclose(file);
    return names;
}

int compare_strings(const void *a, const void *b);
int compare_strings(const void *a, const void *b)
{
    const char *const *ptr1 = (const char *const *)a;
    const char *const *ptr2 = (const char *const *)b;
    const char *str1 = *ptr1;
    const char *str2 = *ptr2;
    return strcmp(str1, str2);
}

static int
lcore_main(void *operation_mode)
{
    uint16_t port;

    printf("The operation mode is: %s", (char *)operation_mode);

    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) !=
            (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
           rte_lcore_id());

    const char *filename = "/home/ubuntu/dpdk/examples/DNS_TLS/random_strings.txt";
    int num_names;
    char **names = read_names_from_file(filename, &num_names);
    qsort(names, num_names, sizeof(names[0]), compare_strings);

    if (strcmp(operation_mode, "exact_match") == 0)
    {
        for (;;)
        {
            RTE_ETH_FOREACH_DEV(port)
            {
                struct rte_mbuf *bufs[BURST_SIZE];
                uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                                  bufs, BURST_SIZE);
                if (nb_rx > 0)
                {
                    uint64_t timestamp = rte_get_tsc_cycles();
                    uint64_t tsc_hz = rte_get_tsc_hz();
                    double timestamp_us = (double)timestamp / tsc_hz * 1e6;
                    struct rte_ether_hdr *ethernet_header;
                    struct rte_ipv4_hdr *pIP4Hdr;
                    struct rte_tcp_hdr *pTcpHdr;
                    struct rte_tls_hdr *pTlsHdr;
                    struct rte_tls_hello_hdr *pTlsHandshakeHdr;
                    struct rte_tls_session_hdr *pTlsSessionHdr;
                    struct rte_tls_cipher_hdr *pTlsChiperHdr;
                    struct rte_tls_compression_hdr *pTlsCmpHdr;
                    struct rte_tls_ext_len_hdr *pTlsExtLenHdr;
                    struct rte_tls_ext_hdr *pTlsExtHdr;

                    u_int16_t ethernet_type;
                    for (int i = 0; i < nb_rx; i++)
                    {
                        ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                        ethernet_type = ethernet_header->ether_type;
                        ethernet_type = rte_cpu_to_be_16(ethernet_type);

                        if (ethernet_type == 2048)
                        {
                            pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                            uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                            uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);
                            ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
                            if (IPv4NextProtocol == 6)
                            {
                                pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                                uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                                uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                                uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 4;
                                if (dst_port == 443)
                                {

                                    pTlsHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tcpdata_offset);
                                    uint8_t tls_type = pTlsHdr->type;
                                    uint32_t tlsdata_offset = tcpdata_offset + sizeof(struct rte_tls_hdr);
                                    if (tls_type == 0x16)
                                    {
                                        pTlsHandshakeHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hello_hdr *, tlsdata_offset);
                                        uint8_t handshake_type = pTlsHandshakeHdr->type;
                                        tlsdata_offset += sizeof(struct rte_tls_hello_hdr);
                                        if ((handshake_type == 1) | (handshake_type == 2))
                                        {

                                            pTlsSessionHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_session_hdr *, tlsdata_offset);
                                            tlsdata_offset += (pTlsSessionHdr->len) + sizeof(struct rte_tls_session_hdr);

                                            pTlsChiperHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_cipher_hdr *, tlsdata_offset);
                                            uint16_t cipher_len = rte_cpu_to_be_16(pTlsChiperHdr->len);
                                            tlsdata_offset += cipher_len + sizeof(struct rte_tls_cipher_hdr);

                                            pTlsCmpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_compression_hdr *, tlsdata_offset);
                                            tlsdata_offset += pTlsCmpHdr->len + sizeof(struct rte_tls_compression_hdr);

                                            pTlsExtLenHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_len_hdr *, tlsdata_offset);
                                            uint16_t exts_len = rte_cpu_to_be_16(pTlsExtLenHdr->len);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_len_hdr);

                                            while (exts_len > 0)
                                            {
                                                pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                                uint16_t ext_type = rte_cpu_to_be_16(pTlsExtHdr->type);
                                                uint16_t ext_len = rte_cpu_to_be_16(pTlsExtHdr->len);
                                                tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                                if (ext_type == 0)
                                                {
                                                    if (ext_len == 0)
                                                    {
                                                        break;
                                                    }
                                                    uint32_t name_offset = tlsdata_offset + sizeof(struct rte_ctls_ext_sni_hdr);

                                                    const char *server_name = rte_pktmbuf_mtod_offset(bufs[i], char *, name_offset);
                                                    const char **result = (const char **)bsearch(&server_name, names, num_names, sizeof(names[0]), compare_strings);
                                                    // printf("The server name is: %s\n",server_name);
                                                    if (result != NULL)
                                                    {

                                                        uint64_t timestamp2 = rte_get_tsc_cycles();
                                                        double timestamp2_us = (double)timestamp2 / tsc_hz * 1e6;
                                                        double timetaken = timestamp2_us - timestamp_us;
                                                        nb_rx--;
                                                        rte_pktmbuf_free(bufs[i]);
                                                        printf("Exact match: %s is on the blacklist. Time: %.2f microseconds\n", server_name, timetaken);
                                                    }
                                                    break;
                                                }
                                                tlsdata_offset += ext_len;
                                                exts_len -= ext_len - sizeof(struct rte_tls_ext_hdr);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (unlikely(nb_rx == 0))
                        continue;

                    const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                                                            bufs, nb_rx);
                    if (unlikely(nb_tx < nb_rx))
                    {
                        uint16_t buf;

                        for (buf = nb_tx; buf < nb_rx; buf++)
                            rte_pktmbuf_free(bufs[buf]);
                    }
                }
            }
        }
    }

    return 0;
}

static void close_ports(void);
static void close_ports(void)
{
	uint16_t portid;
	int ret;
    uint16_t nb_ports;
    nb_ports = rte_eth_dev_count_avail();
	for (portid = 0; portid < nb_ports; portid++) {
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_stop: err=%s, port=%u\n",
				 strerror(-ret), portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t portid;
    int ret;
    int opt;
    char *operation_mode;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    argc -= ret;
    argv += ret;

    while ((opt = getopt(argc, argv, "p:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            operation_mode = argv[2];
            break;

        default:
            break;
            ;
        }
    }

    nb_ports = rte_eth_dev_count_avail();

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                 portid);

    // rte_eal_mp_remote_launch(lcore_main, NULL, SKIP_MAIN);
    rte_eal_mp_remote_launch(lcore_main, operation_mode, SKIP_MAIN);
    // lcore_main();
    rte_eal_mp_wait_lcore();

    close_ports();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}