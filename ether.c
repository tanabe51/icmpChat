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
#include <netinet/ether.h>
#include "ether.h"

int DriverUp(char *device,int promiscFlag,int ipOnly)
{
	struct ifreq ifreq;
	struct sockaddr_ll sa;
	int soc;

	if(ipOnly){
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP)))<0){
			perror("socket");
			return -1;
		}
	}
	else{
		if((soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0){
			perror("socket");
			return -1;
		}
	}
	
	memset(&ifreq,0,sizeof(struct ifreq));
	strncpy(ifreq.ifr_name,device,sizeof(ifreq.ifr_name)-1);
	if(ioctl(soc,SIOCGIFINDEX,&ifreq)<0){
		perror("ioctl");
		close(soc);
		return -1;
	}

	sa.sll_family = PF_PACKET;
	if(ipOnly){
		sa.sll_protocol = htons(ETH_P_IP);
	}
	else{
		sa.sll_protocol = htons(ETH_P_ALL);
	}
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if(bind(soc,(struct sockaddr *)&sa,sizeof(sa))<0){
		perror("bind");
		return -1;
	}

	if(promiscFlag){
		if(ioctl(soc,SIOCGIFFLAGS,&ifreq)<0){
			perror("ioctl");
			close(soc);
			return -1;
		}
		ifreq.ifr_flags = ifreq.ifr_flags|IFF_PROMISC;
		if(ioctl(soc,SIOCGIFFLAGS,&ifreq)<0){
			perror("ioctl");
			close(soc);
			return -1;
		}
	}

	return soc;
}

int Ether(int UpperLen,u_char *UpperPkt,
		char *hdst,char *hsrc,u_int16_t type)
{
	u_int8_t Upper[1514-sizeof(struct ether_header)];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);
	struct ether_header *eh;
	u_int8_t *ptr;

	ptr = (u_int8_t *)UpperPkt;
	eh = (struct ether_header *)ptr;
	memset(eh,0,sizeof(struct ether_header));
	memcpy(eh->ether_dhost,ether_aton(hdst),6);
	memcpy(eh->ether_shost,ether_aton(hsrc),6);
	eh->ether_type = htons(type);
	ptr += sizeof(struct ether_header);
	memcpy(ptr,Upper,UpperLen);
	ptr += UpperLen;
	
	return UpperLen+sizeof(struct ether_header);
}

int Arp(int UpperLen,u_char *UpperPkt,u_int8_t op,char  *hsrc,char *psrc,
	char *hdst,char *pdst)
{
	u_int8_t Upper[1500];
	memcpy(Upper,UpperPkt,UpperLen);
	memset(UpperPkt,0,UpperLen);
	struct ether_arp *arp;
	u_int8_t *ptr;

	ptr = (u_int8_t *)UpperPkt;
	arp = (struct ether_arp *)ptr;
	memset(arp,0,sizeof(struct ether_arp));
	arp->arp_hrd = htons(0x0001);
	arp->arp_pro = htons(0x0800);
	arp->arp_hln = 0x6;
	arp->arp_pln = 0x4;
	arp->arp_op = htons(op);
	memcpy(arp->arp_sha,ether_aton(hsrc),6);
	inet_aton(psrc,(struct in_addr *)&(arp->arp_spa));
	memcpy(arp->arp_tha,ether_aton(hdst),6);
	inet_aton(pdst,(struct in_addr *)&(arp->arp_tpa));
	return UpperLen+sizeof(struct ether_arp);
}

