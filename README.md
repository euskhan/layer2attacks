# Layer 2 Attacks
[TR] 

Temel 2.Katman saldırıları.

Bu Proje Düzce Üniversitesi/Bilgisayar Mühendisliği Bitirme Projesi Kapsamında sadece EĞİTİM ve AKADEMIK  amaçlar için yapılmıştır.

Oğuz Han Ayaz Tarafından kodlanmıştır.

1. İndirme :
- Kod buradaki repo üzerinden erişime açıktır. [repo] (https://github.com/euskhan/layer2attacks)

2. Önşartlar :
- libpcap (Bu adresten erişilebilir => http://www.tcpdump.org/)
- libnet (Bu adresten erişilebilir => http://libnet.sourceforge.net/)

3. Öneriler :

- Kali - Linux kullanmanızı öneririm çünkü gerekli içeriklerden bazıları (GCC Derleyicisi,Wireshark vs.) halihazırda entegre olarak gelmekte.
- Sanal makine üzerinden bir ağ oluşturup sadece oluşturduğunuz bu ağ üzerinde çalışmak istenirse ek olarak WMware yada VirtualBox gibi programlar kullanılabilir (Kişisel tavsiyem VMware'dir).

4. Derleme Komutları :
- MAC flooding  : "$ make flood"
- ARP flooding  : "$ make arpflooder"
- DNS hijacking : "$ make dns'
- ARP Poisoning : "$ make arpspoofer"
- Hepsi		: "$ make all"

5. Kullanım :
- MAC flooding Saldırısı : "$ ./MACFlooder <sahte mac adres sayisi>"

Belirlediğiz sayıda mac adresini rasgele IP ve katman 2 adresleriyle gönderir.
- ARP flooding Saldırısı :  "$ ./ARPFlooder <Arp tablosuna gonderilecek bos istek sayisi>"

Belirlediğiniz sayıda gratuitous ARP paketlerini gönderecek.
- DNS Hijack Saldırısı : "./DNSHijacker [<Yönlendirilecek IP Adresi> [<Hedef/Kurban IP Adresi>]]>"

2 değişkende isteğe bağlı, ancak Hedef IP Adresi yani 2.seçeneği kullanmak istiyorsanız 1. seçeniğide özelleştirmeniz gerekmekte. 
İlk değişken, ziyaret etmeye çalıştıkları web sitesi ne olursa olsun kurbanlarınızı yönlendirdiğiniz IP adresidir.
Defualt değer ise 79.123.223.60 (Düzce Üniversitesi websitesi). 
İkinci değişken ise, ağda direkt olarak hedef aldığınız bir kişi yani kurbanınızın IP adresidir.
- ARP Spoofing(Poision) Saldırısı : "$ ./ARPspoofing <Hedef IP adres>"

Belirlemiş olduğunuz IP Adresine sürekli olarak "gratuitous ARP" paketleri gönderir. Komutun çalışması sonsuz olduğundan "CTRL+C" ile durdurabilirsiniz.

[ENG] 

Basic Layer 2 Attacks.

This Project has been made only for ACADEMIC and EDUCATIONAL purposes within the scope of Duzce University / Computer Engineering Graduation Project.

Codded by Oğuz Han Ayaz.

1. Download :
- Code available on this [repo] (https://github.com/euskhan/layer2attacks)

2. Prerequisites :
- libpcap (it can be accessable from here => http://www.tcpdump.org)
- libnet (it can be accessable from here => http://libnet.sourceforge.net)

3. Suggestions :
- I suggest to use Kali - Linux because neccesary components (like GCC,WireShakr etc.) pre-installed on Kali
- If you want to create a network through a virtual machine and only work on the network you have created,you need to install additional programs like WMware or VirtualBox (My personal advice is VMware).

4.Compliation commands :
- MAC flooding  : "$ make flood"
- ARP flooding  : "$ make arpflooder"
- DNS hijacking : "$ make dns'
- ARP Poisoning : "$ make arpspoofer"
- All 		: "$ make all`

5. Usage :
- MAC flooding attack : "./MACFlooder <number of messages>"

It will send random MAC Addresses (as many times as you specify) on the network with random IP and layer 2 addresses.
- ARP flooding attack :  "./ARPFlooder <number of messages>"

It will send random ARP messages (as many times as you specify).
- DNS hijacking attack : "./DNSHijacker [<IP addr answered> [<IP addr to target/victim>]]>"

Both variables are optional, but if you define specific target/victim (it means 2nd option), you need to define first variable.
The first variable is the IP address to where you redirect your victims. By default it is 79.123.223.60 (Duzce Univercity's website). The second one is the IP address of your Victim/Target
ARP spoofing attack : "./ARPspoofing <IP addr>"

It will send gratuitous ARP with the specified IP address on link layer broadcast, until stop with "CTRL+C".
