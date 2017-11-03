int DriverUp(char *device,int promiscFlag,int ipOnly);
int Ether(int UpperLen,u_char *UpperPkt,char *hdst,char *hsrc,u_int16_t type);
int Arp(int UpperLen,u_char *UpperPkt,u_int8_t op,char *hsrc,char *psrc,char *hdst,char *pdst);
