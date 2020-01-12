/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

#ifndef HEADER_H_
#define HEADER_H_
#define __BYTE_ORDER __LITTLE_ENDIAN


//ipv4 header yapisi

//	0                   1                   2                   3
//	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |Version|  IHL  |Type of Service|          Total Length         |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |         Identification        |Flags|      Fragment Offset    |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |  Time to Live |    Protocol   |         Header Checksum       |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                       Source Address                          |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Destination Address                        |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	 |                    Options                    |    Padding    |
//	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
  };


//ethernet headeri
#define ETH_ALEN	6		/* tek bir ethernet adresindeki sekizli	 */

struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* hedef ethernet adresi	*/
	unsigned char	h_source[ETH_ALEN];	/* kaynak ethernet adresi	*/
	unsigned short	h_proto;		/* paket turu ID'si	*/
} __attribute__((packed));



//udp header yapisi
//
//	  0      7 8     15 16    23 24    31
//	 +--------+--------+--------+--------+
//	 |     Source      |   Destination   |
//	 |      Port       |      Port       |
//	 +--------+--------+--------+--------+
//	 |                 |                 |
//	 |     Length      |    Checksum     |
//	 +--------+--------+--------+--------+
//	 |
//	 |          data octets ...
//	 +---------------- ...

struct udphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int16_t	len;
  u_int16_t	check;
};




FILE *logfile;  

//Günlük dosyasýndaki yakalanan paketler hakkýnda bilgi yazdýrma iþlevleri
void print_ip_packet(const u_char * );
void print_udp_packet(const u_char *);
void PrintData (const u_char * , int);

#endif /* HEADER_H_ */
