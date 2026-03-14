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
#include <time.h>

#define MAX_CONNECTIONS 500
#define MAX_TRACKED_IPS 100

#define TCP_STATE_SYN_SENT 1
#define TCP_STATE_SYN_ACK 2
#define TCP_STATE_ESTABLISHED 3
#define TCP_STATE_FINISHED 4

struct connection_entry
{
  unsigned int src_ip;
  unsigned int dst_ip;
  unsigned short src_port;
  unsigned short dst_port;
  unsigned char protocol;
  unsigned char tcp_flags;
  int tcp_state;
  int packet_count;
  time_t first_seen;
  time_t last_seen;
};

struct connection_entry conn_table[MAX_CONNECTIONS];

struct syn_tracker
{
  unsigned int ip;
  int syn_count;
};



struct syn_tracker trackers[MAX_TRACKED_IPS];

void detect_syn_scan(unsigned int source_ip);
void detect_syn_flood();
void update_connection(unsigned int src_ip, unsigned int dst_ip, unsigned short src_port,
                       unsigned short dst_port, unsigned char protocol, unsigned char tcp_flags);

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
  unsigned char flags = 0;
  
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
  
  if(tcp->syn) flags |= 0x02;
  if(tcp->ack) flags |= 0x10;
  if(tcp->fin) flags |= 0x01;
  
  if(tcp->syn == 1 && tcp->ack == 0)
  {
    detect_syn_scan(ip->saddr);
  }
  
  update_connection(ip->saddr, ip->daddr,ntohs(tcp->source), ntohs(tcp->dest),ip->protocol, 
  flags);
  
  detect_syn_flood();
  
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
  
  update_connection(ip->saddr, ip->daddr,ntohs(udp->source),ntohs(udp->dest), ip->protocol, 0);
   detect_syn_flood();
}

void detect_syn_scan(unsigned int source_ip)
{
  for(int i =0; i<MAX_TRACKED_IPS; i++)
  {
    if(trackers[i].ip == source_ip)
    {
      trackers[i].syn_count++;
      if(trackers[i].syn_count > 20)
      {
        struct in_addr addr;
        addr.s_addr = source_ip;
        printf("\n*** Possible SYN Scan Detected from %s ***\n",inet_ntoa(addr));
      }
      return;
    }
    if(trackers[i].ip == 0)
    {
      trackers[i].ip = source_ip;
      trackers[i].syn_count = 1;
      return;
    }
  }
}

void update_connection(unsigned int src_ip, unsigned int dst_ip, unsigned short src_port,
                       unsigned short dst_port, unsigned char protocol, unsigned char tcp_flags)
{
  time_t now = time(NULL);
  for(int i = 0; i < MAX_CONNECTIONS; i++)
  {
    if(conn_table[i].src_ip == src_ip &&
      conn_table[i].dst_ip == dst_ip &&
      conn_table[i].src_port == src_port &&
      conn_table[i].dst_port ==dst_port &&
      conn_table[i].protocol == protocol)
    {
      conn_table[i].packet_count++;
      conn_table[i].tcp_flags = tcp_flags;
      conn_table[i].last_seen = now;
      
      return;
    }
  } 
  
  for(int i =0; i<MAX_CONNECTIONS; i++)
  {
    if(conn_table[i].src_ip == 0)
    {
      conn_table[i].src_ip = src_ip;
      conn_table[i].dst_ip = dst_ip;
      conn_table[i].src_port = src_port;
      conn_table[i].dst_port = dst_port;
      conn_table[i].protocol = protocol;
      conn_table[i].tcp_flags = tcp_flags;
      conn_table[i].packet_count = 1;
      conn_table[i].first_seen = now;
      conn_table[i].last_seen = now;
      return;
    }
  }
  
  int oldest_idx = 0;
  time_t oldest_time = conn_table[0].last_seen;
  
  for(int i = 1; i < MAX_CONNECTIONS; i++)
  {
    if(conn_table[i].last_seen < oldest_time)
    {
      oldest_time = conn_table[i].last_seen;
      oldest_idx = i;
    }
  }
  
  conn_table[oldest_idx].src_ip = src_ip;
  conn_table[oldest_idx].dst_ip = dst_ip;
  conn_table[oldest_idx].src_port = src_port;
  conn_table[oldest_idx].dst_port = dst_port;
  conn_table[oldest_idx].protocol = protocol;
  conn_table[oldest_idx].tcp_flags = tcp_flags;
  conn_table[oldest_idx].packet_count = 1;
  conn_table[oldest_idx].first_seen = now;
  conn_table[oldest_idx].last_seen = now;
  
  if(protocol == 6)
  {
    if(tcp_flags & 0x02)
    	conn_table[i].tcp_state = TCP_STATE_SYN_SENT;
    
    if((tcp_flags & 0x12) == 0x12)
    	conn_table[i].tcp_state = TCP_STATE_SYN_ACK;
    
    if(tcp_flags & 0x10)
    	conn_table[i].tcp_state = TCP_STATE_ESTABLISHED;
    	
    if(tcp_flags & 0x01)
    	conn_table[i].tcp_state = TCP_STATE_FINISHED;
  }
}

void detect_syn_flood()
{
  int half_open = 0;
  for(int i=0; i<MAX_CONNECTIONS; i++)
  {
     if(conn_table[i].protocol == 6 && conn_table[i].tcp_state == TCP_STATE_SYN_SENT)
     {
       half_open++;
     }
  }
  if(half_open > 50)
  {
    printf("\n!!!POSSIBLE SYN FLOOD DETECTED!!!\n");
    printf("Half-open connections: %d\n",half_open);
  }
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
  memset(trackers,0,sizeof(trackers));
  memset(conn_table, 0, sizeof(conn_table));
  while(1)
  {
    static int counter = 0;
    counter++;
    
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
    
  if(counter % 50 == 0)
  {
    printf("\n === connection Table === \n");
  
  
  for(int i = 0; i < MAX_CONNECTIONS; i++)
  {
    if(conn_table[i].src_ip != 0)
    {
      struct in_addr src, dst;
      src.s_addr = conn_table[i].src_ip;
      dst.s_addr = conn_table[i].dst_ip;
      
      printf("%s:%d -> %s:%d, Proto: %d, Packets: %d\n", inet_ntoa(src), conn_table[i].src_port,
      inet_ntoa(dst), conn_table[i].dst_port,conn_table[i].protocol, conn_table[i].packet_count);
      }
    } 
  }
  }
  
  
  return 0;
}
