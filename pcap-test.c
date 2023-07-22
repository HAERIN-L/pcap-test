#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
//#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_off;        /* data offset */
//#endif
//#if (LIBNET_BIG_ENDIAN)
//    u_int8_t th_off:4,        /* data offset */
//           th_x2:4;         /* (unused) */
//#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

struct libnet_ipv4_hdr *ipv4;
struct libnet_tcp_hdr *tcp;
struct libnet_ethernet_hdr *ethernet;

void print_mac(u_int8_t *mac){
   printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

typedef struct {
   char* dev_;
} Param;

Param param = {
   .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet); 

	  const u_char* packet1;
	  packet1 = packet;
		//packet의 시작점이 packet에 담겨있음, 여기서 +하면 점점 아래로 내려갈거임.. 아마도..  
      if (res == 0) continue; 
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
      printf("----------------------------------------\n");
      printf("%u bytes captured\n", header->caplen);

      struct libnet_ethernet_hdr *ethernet_hdr = (struct libnet_ethernet_hdr *)packet;
			//위에 이더넷 헤더 가져옴 , 이더넷의 start host, 
      printf("Source MAC Address\n");
	  print_mac(ethernet_hdr->ether_shost); // 출발지 호스트 가져온 것
      printf("Destination MAC Address\n");
	  print_mac(ethernet_hdr->ether_dhost);  // 도착지 호스트 가져온 것
      //----- > 출발지 MAC 주소랑, 도착지 MAC 주소 가져옴. 1번 과제 끝
      
	  printf("IPv4\n");
      if(ntohs(ethernet_hdr->ether_type) == 0x0800) {
         // 이더넷 타입이 0x0800인 경우 IPv4 패킷임
		  packet += sizeof(struct libnet_ethernet_hdr); // 패킷 포인터를 이더넷 헤더 다음으로 이동시켜서 IPv4 가리키도록 함
		  ipv4 = (struct libnet_ipv4_hdr *)packet;
	  
	  printf("Source IP Address: %s\n", inet_ntoa(ipv4->ip_src));
	  printf("Destination IP Address: %s\n", inet_ntoa(ipv4->ip_dst));

     
     printf("TCP\n");
     packet += sizeof(struct libnet_ipv4_hdr);
     tcp = (struct libnet_tcp_hdr *)packet; // 패킷 포인터 IPv4 헤더 다음으로 이동시켜서 TCP 헤더 가리키도록 함

     printf("Source Port: %d\n", ntohs(tcp->th_sport));
     printf("Destination Port: %d\n", ntohs(tcp->th_dport));


     printf("Payload:");
     int tcp_header_length = (tcp->th_off>>4)*4;
     int payload_offset = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_header_length;
     //printf("%d TCP: %d\n",payload_offset, tcp_header_length);

	 
	 if(payload_offset < header->caplen){
		 for(int i=payload_offset; i<10+payload_offset; i++){
			 printf("%02x ", packet1[i]);
	 
		 }
	 }

	 
        printf("\n");
	 
      }
   }
   pcap_close(pcap);
}
