#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include "checksum.h"
#include "icmp.h"

int Icmp(int UpperLen,u_char *UpperPkt,u_int8_t type,u_int8_t code)
{
	u_int8_t Upper[1500-sizeof(struct iphdr)];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);
	struct icmphdr *icmp;
	u_int8_t *ptr;

	ptr = (u_int8_t *)UpperPkt;
	icmp = (struct icmphdr *)ptr;

	icmp->type = type;
	icmp->code = code;
	icmp->checksum = 0;
	srand(time(NULL));
	icmp->un.echo.id = rand()%0x15;
	srand(time(NULL));
	icmp->un.echo.sequence = rand()%0x10;
	ptr += sizeof(struct icmphdr);
	memcpy(ptr,Upper,UpperLen);
	ptr += UpperLen;
	icmp->checksum = checksum((u_char *)icmp,sizeof(struct icmphdr)+UpperLen);

	return UpperLen+sizeof(struct icmphdr);
}

