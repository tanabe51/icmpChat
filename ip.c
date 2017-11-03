#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "ether.h"
#include "checksum.h"

int Ip(int UpperLen,u_char *UpperPkt,u_int8_t protocol,char *psrc,char *pdst)
{
	u_int8_t Upper[1514-sizeof(struct ether_header)];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);
	struct iphdr *ip;
	u_int8_t *ptr;
	srand(time(NULL));

	ptr = (u_int8_t *)UpperPkt;
	ip = (struct iphdr *)ptr;
	memset(ip,0,sizeof(struct iphdr));
	ip->version = 0x4;
	ip->ihl = 0x5;
	ip->tos = 0x00;
	ip->tot_len = htons(UpperLen + sizeof(struct iphdr));
	ip->id = rand()/0xffff;
	ip->frag_off = 0x0000;
	ip->ttl = 0x80;
	ip->protocol = protocol;
	inet_aton(psrc,(struct in_addr *)&(ip->saddr));
	inet_aton(pdst,(struct in_addr *)&(ip->daddr));
	ip->check = checksum((u_char *)ip,sizeof(struct iphdr)+UpperLen);
	ptr += sizeof(struct iphdr);
	memcpy(ptr,Upper,UpperLen);
	ptr += UpperLen;
	return UpperLen+sizeof(struct iphdr);
}
