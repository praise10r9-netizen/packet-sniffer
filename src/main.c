#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

void print_ethernet_header(unsigned char *buffer)
{
  struct ethhdr *eth = (struct ethhdr*)buffer;
  printf("\nEthernet Header\n");
  
  printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
  eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
  
  printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->h_dest[0],
  eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
  
  printf("Protocol: %u\n",ntohs(eth->h_proto));
}

void print_ip_header(unsigned char *buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  
  struct sockaddr_in src, dest;
  
  memset(&src, 0,sizeof(src));
  src.sin_addr.s_addr = ip->saddr;
  
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = ip->daddr;
  
  printf("\nIP Header\n");
  printf("Source IP: %s\n", inet_ntoa(src.sin_addr));
  
  printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
  printf("Protocol: %d\n",ip->protocol);
}

void print_tcp_header(unsigned char* buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  
  unsigned short iphdrlen = ip->ihl * 4;
  
  struct tcphdr *tcp = (struct tcphdr*) (buffer + sizeof(struct ethhdr) + iphdrlen);
  
  printf("\nTCP Header\n");
  
  printf("Source Port: %u\n", ntohs(tcp->source));
  
  printf("Destination Port: %u\n", ntohs(tcp->dest));
  
  printf("Sequence Number: %u\n", ntohl(tcp->seq));
  
  printf("Acknowledgement Number: %u\n", ntohl(tcp->ack_seq));
  
  printf("Flags:\n");
  printf("SYN: %d\n", tcp->syn);
  printf("ACK: %d\n", tcp->ack);
  printf("FIN: %d\n", tcp->fin);
  printf("RST: %d\n", tcp->rst);
  
}

void print_udp_header(unsigned char *buffer)
{
  struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  
  unsigned short iphdrlen = ip-> ihl * 4;
  
  struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
  
  printf("\nUDP Header\n");
  printf("Source Port: %d\n", ntohs(udp->source));
  printf("Destination Port: %d\n", ntohs(udp->dest));
  printf("Length: %d\n", ntohs(udp->len));
}
int main()
{
 unsigned char buffer[65536];
  int sock_raw;
  sock_raw = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
  
  if(sock_raw < 0)
  {
    perror("Socket Error");
    return 1;
  }
  printf("Packet sniffer started...\n");
  while(1)
  {
    int data_size;
    data_size = recvfrom(sock_raw, buffer, sizeof(buffer),0,NULL,NULL);
    if(data_size < 0)
    {
      perror("Recvfrom error");
      return 1;
    }
    printf("Packet captured: %d bytes\n",data_size);
    
    print_ethernet_header(buffer);
    print_ip_header(buffer);
    
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    switch(ip->protocol)
    {
      case 6:
      	print_tcp_header(buffer);
      	break;
      case 17:
      	print_udp_header(buffer);
      	break;
      	
      default:
      	printf("\nOther Protocol\n");
      	break;
    }
  }
  return 0;
}
