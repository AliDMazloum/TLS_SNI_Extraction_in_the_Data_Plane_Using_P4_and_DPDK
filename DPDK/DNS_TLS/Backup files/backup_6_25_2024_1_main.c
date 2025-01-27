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
#define BURST_SIZE 32

#define FIFO_PATH "/tmp/my_fifo"

#define IPV4_PROTO 2048
uint64_t total_pkts;

typedef struct
{
    rte_be32_t words[8]; // Assuming 32-bit words
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

struct rte_tls_hdr {
	/** Content type of TLS packet. Defined as RTE_TLS_TYPE_*. */
	uint8_t type;
	/** TLS Version defined as RTE_TLS_VERSION*. */
	rte_be16_t version;
	/** The length (in bytes) of the following TLS packet. */
	rte_be16_t length;
} __rte_packed;

struct rte_tls_hello_hdr
{
    uint8_t type;
    uint24_t len;
    rte_be16_t  version;
    uint256_t random;
}__rte_packed;


struct rte_tls_session_hdr
{
    uint8_t len;
}__rte_packed;

struct rte_tls_cipher_hdr
{
    uint16_t len;
    // In Client: ciphers follow
}__rte_packed;

struct rte_tls_compression_hdr
{
    uint8_t len;
    //  In Client: compressions follow
}__rte_packed;

struct rte_tls_ext_len_hdr
{
    uint16_t len;
}__rte_packed;

struct rte_tls_ext_hdr
{
    uint16_t type;
    uint16_t len;
}__rte_packed;

struct rte_ctls_ext_sni_hdr
{
    uint16_t sni_list_len;
    uint8_t type;
    uint16_t sni_len;
}__rte_packed;

struct rte_server_name
{
    uint16_t name;
}__rte_packed;

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

static int
lcore_main(void *)
{
    uint16_t port;

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

    for (;;)
    {
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                                    bufs, BURST_SIZE);
            if (nb_rx > 0)
            {
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
                struct rte_ctls_ext_sni_hdr *pCtlsExtSniHdr;

                u_int16_t ethernet_type;
                for (int i = 0; i < nb_rx; i++)
                {

                    ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                    ethernet_type = ethernet_header->ether_type;
                    ethernet_type = rte_cpu_to_be_16(ethernet_type);
                    // printf("EtherType is: %u \n", ethernet_type);

                    if (ethernet_type == 2048)
                    {
                        pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                        uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                        uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);
                        ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
                        // printf("IPv4NextProtocol is: %u \n", IPv4NextProtocol);
                        if (IPv4NextProtocol == 6)
                        {
                            pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                            uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                            uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                            uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 8;
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
                                    // printf("handshake_type is: %u \n", handshake_type);
                                    if ((handshake_type == 1) | (handshake_type == 2))
                                    {
                                        pTlsSessionHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_session_hdr *, tlsdata_offset);
                                        tlsdata_offset += (pTlsSessionHdr->len) + sizeof(struct rte_tls_session_hdr);
                                        // printf("tlsdata_offset is: %u \n", tlsdata_offset);

                                        pTlsChiperHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_cipher_hdr *, tlsdata_offset);
                                        uint16_t cipher_len = rte_cpu_to_be_16(pTlsChiperHdr->len);
                                        tlsdata_offset += cipher_len + sizeof(struct rte_tls_cipher_hdr);
                                        // printf("cipher_len is: %u \n", cipher_len);

                                        pTlsCmpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_compression_hdr *, tlsdata_offset);
                                        tlsdata_offset += pTlsCmpHdr->len + sizeof(struct rte_tls_compression_hdr);
                                        // printf("pTlsCmpHdr->len is: %u \n", pTlsCmpHdr->len);

                                        pTlsExtLenHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_len_hdr *, tlsdata_offset);
                                        uint16_t ext_len = rte_cpu_to_be_16(pTlsExtLenHdr->len);
                                        tlsdata_offset += sizeof(struct rte_tls_ext_len_hdr);
                                        // printf("ext_len is: %u \n", ext_len);/

                                        if (ext_len > 0)
                                        {
                                            pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                            uint16_t ext_type = rte_cpu_to_be_16(pTlsExtHdr->type);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                            printf("ext_type is: %u \n", ext_type);
                                            if (ext_type == 0)
                                            {
                                                pCtlsExtSniHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ctls_ext_sni_hdr *, tlsdata_offset);
                                                uint16_t sni_list_len = rte_be_to_cpu_16(pCtlsExtSniHdr->sni_list_len);
                                                uint8_t sni_type = pCtlsExtSniHdr->type;
                                                uint16_t sni_len = rte_cpu_to_be_16(pCtlsExtSniHdr->sni_len);
                                                // printf("sni_list_len is: %u, the type is %u, and the sni_len is %u \n", sni_list_len,sni_type,sni_len);
                                                // printf("Ali\n");
                                                tlsdata_offset += sizeof(struct rte_ctls_ext_sni_hdr);
                                                char * server_name;
                                                server_name = malloc(sni_len);
                                                server_name = rte_pktmbuf_mtod_offset(bufs[i], char *, tlsdata_offset);
                                                // uint16_t server_int = rte_be_to_cpu_16(server_name->name);
                                                printf("The servername is: %s \n",server_name);
                                            }
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
    return 0;
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t portid;
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

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
    rte_eal_mp_remote_launch(lcore_main, NULL, SKIP_MAIN);
    // lcore_main();
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}