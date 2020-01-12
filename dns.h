
#ifndef DNS_H_
#define DNS_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;

#define BUF_SIZE 65536
#define HOST_NAME_SIZE 100
#define TYPE_A 1



#define CLASS_IN 1	// internet baglantisi



// DNS header yapisi
//                                  1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                      ID                       |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                QDCOUNT/ZOCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                ANCOUNT/PRCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                NSCOUNT/UPCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ARCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


// kod_Baslangic
/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

struct dns_header
{
	uint16_t id;
		// ID	 		Program tarafindan atanan 16 bit tanimlayici
		//		 		her turlu sorguyu uretir. 
		//		 		Bu tanimlayici karsilik gelen yaniti kopyalar ve 
		// 				istekte bulunan tarafindan yanitlari bekleyen sorgularla eslestirmek icin kullanilabilir.
	
	uint16_t flags;        // Bit alanlari kullanmadan sentezlenmis flagler 

	uint16_t qd_count;
		//	QDCOUNT         question bolumundeki giris sayisini belirten isaretsiz bir 16 bit tam sayi.
	uint16_t an_count;
		//	ANCOUNT         answer bolumundeki kaynak kayitlarinin sayisini belirten isaretsiz bir 16 bit tam sayi.
	uint16_t ns_count;
		//	NSCOUNT        authority records bolumunde kaynak kayitlarinin sayisini belirten isaretsiz bir 16 bit tam sayi.
	uint16_t ar_count;
		//	ARCOUNT        additional records bolumundeki kaynak kayitlarinin sayisini belirten isaretsiz bir 16 bit tam sayi.

};
typedef struct dns_header dns_header;
void get_domain_name(char *buff, char *name);
//kod_sonu


#endif /* DNS_H_ */
