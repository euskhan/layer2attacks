/*
 *Macof.c (dsniff library)'den esinlenerek Oguz Han Ayaz Tarafindan Yazilmistir.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

#include "dns.h"


void get_domain_name(char *buff, char *domain_name){
	int i;
	for (i=0; domain_name[i] != 0; i++){
		if ((unsigned char) domain_name[i] <= 63)
			buff[i] = '.';
		else
			buff[i] = domain_name[i];
	}
	buff[i] = 0;
}
