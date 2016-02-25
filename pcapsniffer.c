#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>

//datalink layer header size.
int linkhdrlen;
//number of tcp/udp/icmp packets captured.
int tcpn = 0, udpn = 0, icmpn = 0; 

//Receives a packet, checks its protocol and prints it.
void callback(u_char *user, const struct pcap_pkthdr *packethdr, u_char *packetptr)
{
    struct ip* ipheader;
	struct tcphdr* tcpheader;
    struct icmphdr* icmpheader;
    struct udphdr* udpheader;
    char ipheaderInfo[256], srcip[256], dstip[256];

    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    ipheader = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(ipheader->ip_src));
    strcpy(dstip, inet_ntoa(ipheader->ip_dst));
    sprintf(ipheaderInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d Proto: %d", ntohs(ipheader->ip_id), ipheader->ip_tos, ipheader->ip_ttl, 4*ipheader->ip_hl, ntohs(ipheader->ip_len), ipheader->ip_p); //ntohs needed because of little-endian architectures.

    // Advance to the transport layer header.
    packetptr += 4*iphdr->ip_hl;
	
    switch (ipheader->ip_p)
    {
		case IPPROTO_TCP:
			tcpn++;
		
			tcpheader = (struct tcphdr*)packetptr;
			printf("TCP source IP: %s:%d -> Dest IP: %s:%d\n", srcip, ntohs(tcpheader->source), dstip, ntohs(tcpheader->dest));
			printf("%s\n", ipheaderInfo);
			printf("Flags: %c%c%c%c%c%c SeqNumber: 0x%x Ack: 0x%x WinSize: 0x%x TcpLen: %d\n", (tcpheader->urg ? 'U' : '*'), (tcpheader->ack ? 'A' : '*'), (tcpheader->psh ? 'P' : '*'), (tcpheader->rst ? 'R' : '*'), (tcpheader->syn ? 'S' : '*'), (tcpheader->fin ? 'F' : '*'), ntohl(tcpheader->seq), ntohl(tcpheader->ack_seq), ntohs(tcpheader->window), 4*tcpheader->doff);
			break;

		case IPPROTO_UDP:
			udpn++;
		
			udpheader = (struct udpheader*)packetptr;
			printf("UDP source IP: %s:%d -> Dest IP: %s:%d\n", srcip, ntohs(udpheader->source), dstip, ntohs(udpheader->dest));
			printf("%s\n", ipheaderInfo);
			break;

		case IPPROTO_ICMP:
			icmpn++;
	 
			icmpheader = (struct icmphdr*)packetptr;
			printf("ICMP source IP: %s -> Dest IP: %s\n", srcip, dstip);
			printf("%s\n", ipheaderInfo);
			printf("Type:%d Code:%d\n", icmpheader->type, icmpheader->code);
			break;
    }
    printf(
        "-----------------------------------------------------------\n\n");
}

int main(int argc,char **argv)
{
	//device where traffic is to be captured
    char *dev; 
	//Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
	//structure to hold packet
    pcap_t* descr;
	//compiled filter expression
    struct bpf_program fp;
    //mask of the subnet	
    bpf_u_int32 Mask; 
	//network ip address
    bpf_u_int32 Net; 
	
    // Check number of arguments
    if(argc != 3)
    {
        printf("Wrong number of arguments!\n",argv[0]);
        return 0;
    }
	
	//interface to be sniffed
    dev = "eth0";

    // get network address and mask
    pcap_lookupnet(dev, &Net, &Mask, errbuf);

    // open device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() error: [%s]\n", errbuf);
        return -1;
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, argv[1], 0, Mask) == -1)
    {
        printf("pcap_compile() error\n");
        return -1;
    }

    // Set the filter compiled above
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("pcap_setfilter() error\n");
        exit(1);
    }

    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(descr)) < 0)
    {
        printf("pcap_datalink() error: %s\n", pcap_geterr(descr));
        return;
    }
	
    // Set the datalink layer header size, to later skip the header and get to the IP header in the callback function
    switch (linktype)
    {
		case DLT_NULL:
			linkhdrlen = 4;
			break;
	
		case DLT_EN10MB:
			linkhdrlen = 14;
			break;

		default:
			printf("Unknown datalink (%d)!\n", linktype);
			return;
    }

	//sends every packet received to callback to be treated
    pcap_loop(descr,atoi(argv[2]), callback, NULL);

   //simple counter for packet protocol
   if(tcpn > udpn){
	   if(tcpn > icmpn)
			printf("traffic majority is tcp.\n");
		else
			printf("traffic majority is icmp.\n");
    }else if (udpn > icmpn){
        printf("traffic majority is udp.\n");
    }else
		printf("traffic majority is icmp.\n")
	
    return 0;
}



