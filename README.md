# Layer 2 Attacks
[TR] Temel 2.Katman saldırıları.

Bu Proje Düzce Üniversitesi/Bilgisayar Mühendisliği Bitirme Projesi Kapsamında sadece EĞİTİM ve AKADEMIK amaçlar için yapılmıştır.

Oğuz Han Ayaz Tarafından kodlanmıştır.

1. İndirme
Kod buradaki repo üzerinden erişime açıktır. [repo] (https://github.com/euskhan/layer2attacks)

2. Önşartlar :
- libpcap (Bu adresten erişilebilir => http://www.tcpdump.org/)
- libnet (Bu adresten erişilebilir => http://libnet.sourceforge.net/)

3. Öneriler

- Kali - Linux kullanmanızı öneririm çünkü gerekli içeriklerden bazıları (GCC Derleyicisi,Wireshark vs.)
- Sanal makine üzerinden bir ağ oluşturup sadece oluşturduğunuz bu ağ üzerinde çalışmak istenirse ek olarak WMware yada VirtualBox gibi programlar kullanılabilir (Kişisel tavsiyem VMware'dir).

4. Derleme Komutları:
- MAC flooding  : '$ make flood'
- ARP flooding  : '$ make arpflooder'
- DNS hijacking : '$ make dns'
- ARP Poisoning : '$ make arpspoofer'
- Hepsi		: `$ make all`

5. Kullanım
- MAC Flood Saldırısı: './MACFlooder <MAC Adres Sayısı>'
-Belirttiğiniz sayıda MAC Adresini ağa rastgele IP Adresi ve 2nci Katman Adresi ile birlikte gönderecektir.
- ARP Flood Saldırısı:  './ARPFlooder <Gönderilecek ARP Paket Sayısı>'
-Belirttiğiniz sayıda ARP Paketini gönderecektir.
- DNS Hijack Saldırısı : './DNSHijacker [<Yönlendirilecek IP Adresi> [<Hedef/Kurban IP Adresi>]]>'
İki değişkende isteğe bağlıdır , ancak Hedef/Kurban'a ait bir IP Adresi kullanabilmek için ilk değişkeni bir diğer deyişle kurbanı yönlendirmek istediğiniz ip adresini girmeniz gerekmektedir
İlk değişkenin varsayılan değeri 79.123.223.60 (Düzce Üniversitesi'nin websitesidir).
- ARP Spoofing/Poisoning Saldırısı: './ARPspoofing <IP Adresi>'
Siz 'CTRL+C' ile durdurana dek, bağlantı katmanı yayınında belirtilen IP adresi ile karşılıksız ARP gönderecektir.

[ENG] 
Basic Layer 2 Attacks.

This Project has been made only for ACADEMIC and EDUCATIONAL purposes within the scope of Duzce University / Computer Engineering Graduation Project

Codded by Oğuz Han Ayaz

1. Download
Code available on this [repo] (https://github.com/euskhan/layer2attacks)

2. Prerequisites :
- libpcap (it can be accessable from here => http://www.tcpdump.org)
- libnet (it can be accessable from here => http://libnet.sourceforge.net)

3. Suggestions

- I suggest to use Kali - Linux because neccesary components (like GCC,WireShakr etc.) pre-installed on Kali
- If you want to create a network through a virtual machine and only work on the network you have created,you need to install additional programs like WMware or VirtualBox (My personal advice is VMware).

4.Compliation commands:
- MAC flooding  : '$ make flood'
- ARP flooding  : '$ make arpflooder'
- DNS hijacking : '$ make dns'
- ARP Poisoning : '$ make arpspoofer'
- All 		: `$ make all`

5. Usage
- MAC flooding attack : './MACFlooder <number of messages>'
-It will send random MAC Addresses (as many times as you specify) on the network with random IP and layer 2 addresses.
- ARP flooding attack :  './ARPFlooder <number of messages>'
-It will send random ARP messages (as many times as you specify).
- DNS hijacking attack : './DNSHijacker [<IP addr answered> [<IP addr to target/victim>]]>'
Both arguments are optional, but if you define specific target/victim (it means 2nd option), you need to define first argument.
The first argument is the IP address to where you redirect your victims. By default it is 79.123.223.60 (Duzce Univercity's website). The second one is the IP address of your victim, if you want it to be a unique person on the network.
- ARP spoofing attack : './ARPspoofing <IP addr>'
It will send gratuitous ARP with the specified IP address on link layer broadcast, until you stop it with `^C`.

