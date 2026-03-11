#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

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
  }
  return 0;
}
