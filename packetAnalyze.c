#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "checksum.h"
#include "packetAnalyze.h"

int AnalyzeIcmp(u_char *data,int size,u_char *mes)
{
	u_int8_t tmpBuf[1500 - 20];
	memcpy(tmpBuf,data,size);
	u_int8_t *ptr;
	int lest;
	struct icmphdr *icmp;
	

	ptr = tmpBuf;
	lest = size;
	icmp = (struct icmphdr *)ptr;
	if(icmp->type == 0x08){
			ptr += sizeof(struct icmphdr);
			lest -= sizeof(struct icmphdr);
			memcpy(mes,ptr,lest);
			return lest;
	}
	return 0;
}


int AnalyzeIp(u_char *data,int size,u_char *mes)
{
	u_char *ptr;
	int lest;
	struct iphdr *ip;
	ptr = data;
	lest = size;

	ip = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	lest -= sizeof(struct iphdr);

	if(ip->protocol==0x01){
			return AnalyzeIcmp(ptr,lest,mes);
	}
	return 0;
}

int Analyze(u_char *data,int size,u_char *mes)
{
	u_char *ptr;
	int lest;
	struct ether_header *eh;

	ptr = data;
	lest = size;

	eh = (struct ether_header *)ptr;
	ptr +=sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if(ntohs(eh->ether_type)==0x0800){
			return AnalyzeIp(ptr,lest,mes);
	}
	return 0;
}
