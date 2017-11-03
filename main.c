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
#include <pthread.h>
#include "ether.h"
#include "ip.h"
#include "icmp.h"
#include "packetAnalyze.h"

void dump(const void *buf, int size)
{
	int i;
	u_char *p = (u_char *)buf;
	for(i=0;p-(u_char *)buf<size;i++){
		printf("%c",(char)((*p<0x20||*p>=0x7f)? '.': *p));
		p++;
		if (*(u_char *)buf=='\0'){
			break;
		}
	}
}

void *getMessage(void *p)
{	
	int size;
	int lest;
	u_char message[1500 - 20];
	u_char data[1500 - 20];
	for(;;){
		size = read(*(int *)p,message,sizeof(message));
		if((lest = Analyze(message,size,data))){
			printf("Guest>> ");
			dump(data,lest);
			printf("\n");
		}
	}
}

int main(int argc,char *argv[])
{
	int driver;
	int len;
	char *hdst = "";
	char *hsrc = "";
	char *psrc = "192.168.1.";
	char *pdst = "192.168.1.";

	driver = DriverUp(argv[1],0,0);
	pthread_t getMes;
	pthread_create(&getMes,NULL,getMessage,(void *)&driver);
	u_char pkt[1514];
	for(;;){
		memset(pkt,0,sizeof(pkt));
		scanf("%s",pkt);
		len = Ether(Ip(Icmp(strlen((const char*)pkt),pkt,8,0),pkt,0x01,psrc,pdst),pkt,hsrc,hdst,0x0800);
		write(driver,pkt,len);
	}
	return 0;
}
