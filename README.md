# Bezpieka

## 1. Koncepcja triady bezpieczeństwa oraz innych usług ochrony informacji

### Concept of Confidentiality, Integrity and Availability

- Confidentiality (Poufność)
    - Dane i usługi powinny być dostępne tylko dla uprawnionych osób
    - Dane powinny być chronione w trakcie przechowywania, przetwarzania i transmisji
    - __Możliwe ataki__: przechwycenia ruchu sieciowego, kradzież haseł (socjotechniki), skanowanie portów,  (podsłuchiwanie), [sniffing](https://pl.wikipedia.org/wiki/Sniffer)
    - __Formy ochrony__: Dostępu do kont chronią nazwy użytkowników, hasła, wielostopniowe uwierzytelnianie, trasmisja danych jest szyfrowana, personel jest dobrze przeszkolony
    - Uwierzytelnianie (Authentication) - potwierdzenie tożsamości
    - Autoryzacja (Authorization) - potwierdzenie uprawnień
    - Secrecy - Secrecy is the act of keeping something a scret or preventing the disclosure of information
    - Privacy - refers to keeping information confidential that is personally identifiable or that might couse harm, embarrassment or disgrace to someone

- Integrity (Integralność)
    - Dane i usługi powinny być nienaruszone przez podmioty, które nie mają do nich uprawnień
    - Wysoki poziom pewności, że dane zostały niezmienowe przez nieuprawniony podmiot (w trakcie przechowywania, przetwarzania i transmisji)
    - 3 perspektywy integralności
        - Powstrzymanie nieuprawnionego użytkownika przez modyfikacją danych
        - Powstrzymanie uprawnionego użytkownika przez nieuprawnioną modyfikacją danych
        - Utrzymanie wewnętrznej i zewnętrzej spójności danych, tak aby były odzwierciedleniem prawdziwego świata
    - __Możliwe ataki__: wirusy, backdoors, błędy użytkowników [PEBCAC](https://en.wiktionary.org/wiki/PEBCAC#English), przypadkowe usunięcie danych, wprowadzenie niepoprawnych danych, złośliwe modyfikacje
    - __Formy ochrony__: regorystyczna kontrola dostępu, regorystyczne procedury uwierzytelnienia użytkowników, systemy wykrywania intruzów, szyfrowanie danych, szkolenie personelu

- Availavility (Dostępność)
    - Każda uprawniona osoba powinna mieć dostęp do zasobów
    - Odporność na ataki DOS
    - __Możliwe ataki__: awarie urządzeń, oprogramowania, problemy ze środowiskiem (powódź, awaria zasilania), ataki DOS itp.
    - __Formy ochrony__: monitorowanie wydajności i ruchu sieciowego, używanie firewall-i i routerów w celu zapobiegania atakom DOS, redundacja dla krytycznych części systemu (dodatkowe łącze internetowe, generator prądu), system backupów
    - Nonrepudiation (niepodważalność) - zapewnienie, że osoba upoważniona nie otrzyma "odmowy dostepu". Pełną niepodważlność uzyskujemy poprzez wykorzystanie certyfikatów

### Access Control

- Access is the flow of information between a subject(e.g., user, program, process, or device, etc.) and an object (e.g., file, database, program, process, or device, etc.)
- Jest to zestaw mechanizmów, które razem zapewniają ochronę danych przez nieuprawnionym dostępem
- Kontrola dostępu uprawnia do zażądzania
    - Jacy użytkownicy maja mieć dostęp do systemu
    - Jakie zasoby maja być dostępne`
    - Jakie operację mogą być wykonane
    - Dostarcza indywidualną odpowiedzalność // mam wrażenie że chodzi tutaj o to, że każdy użytkownik jest niezależny i może mieć indywidualny zakres uprawnień
- Implementacje
    - _Least privilege_ - ograniczenie uprawnień użytkowników do niezbędnego minimum
    - _Separate od duties_ - proces jest tak zaprojektowany, że jego kroki muszą być wykonane przez róźne osoby (róźne uprawnienia)
- Kategorie kontroli bezpieczeństwa
    - _Management_ - polityki, standardy, procesy, procedury
    - _Operational (and Physical) Controls_ - przestrzeganie procedur, edukacja i świadomość
        - _Physical Security_ - zamki, drzwi, ochrona itp.
    - _Technical Controls_ - Kontrola dostępu, Identyfikacja i uwierzytelnienie, poufność, integralność, dostępnośc i niepodważalność

## 2. Zagrożenia na protokoły sieciowe warstwy 2 i 3 modelu OSI 🏮

### Data link layer protocols

- MAC (LAN & WAN)
- LLC (LAN)
- Ethernet (CSMA/CD)
- Token Ring (Token Passing)
- IEEE 802.11 a/b/g (CSMA/CA)
- WAN Data Link Layer
    - X.25
    - Frame Relay
    - SMDS (Switched Multi-gigabit Data Services)
    - ISDN (Integrated Services Digital Network)
    - HDLC (High-level Data Link Control)
    - ATM (Asynchronous Transfer Mode)
- SLIP (Serial Line Internet Protocol)
    - Kapsułkuje pakiet IP w jedną Serial line (linie szeregową ???)
    - Działa z różnymi protokołami (Token Ring, WAN)
    - Ale może działać tylko z jednym na raz
    - Nie sprawdza błędów transmisji danych
    - Nie zapewnia bezpieczeństwa
- PPP (Point-to-Point Protocol)
    - Mechanizm kapsułkujący do transportu wielo-protokołowych pakietów
    - Zastąpił SLIP bo może pracować z wieloma protokołami na raz i daje możliwośc uwierzytelnienia
    - Security:
        - PAP (Password Authentication Protocol)
            - Plain Text
        - CHAP (Challenge Handshake Authentication Protocol)
            - Chroni przez playback/replay atack używając 3-way handshake
        - EAP (Extensible Authentication Protocol)
            - Wspiera wiele mechanizmów uwierzytelnienia
            - MD5-Challange
            - One-Time Password
            - Generic Token Card
- WEP (Wired Equivalent Privacy)
    - Używa klucza symetrycznego o długości 40 bitów (jest opcja 104-bit, ale to nie standard) z 24 bitowym IV (Initialization Vector)
    - Używa tego samego statycznego klucza do wszytkich połączeń
    - Podatne na:
        - Haker może przechwycić wystarczającą ilość pakietów z takim samym IV i odkryć klucz symetryczny
        - Jeden statyczny, symetryczny klucz i rozmiarze 40 bitów
    - Lepsza wersja to WPA
        - Nie używa tego samego klucza do szyfrowania wszystkich połączeń
    - Jeszcze lepsa wersja WPA2
        - Używa IEEE 802.1X (np. EAP) do uwierzytelnienia
        - Używa 4-way handshake do zarządania kluczami
        - Używa AES-based CCMP (Counter-mode Cipher-block-chaining Message authentication code Protocol)
- EAP (Extensible Authertication Protocol)
- IEEE 802.1X
- ARP
    - Mapuje adresy IP na adresy MAC
    - Podatne na:
        - Man in the Middle
            - Przechwytywanie ruchu między dwoma urządzeniami w sieci
        - MAC Flooding Attack
            - Atak na switche
            - Zalewa switcha falą błędnych odpowiedzi ARP
            - Biedny switch przechodzi w tedy w tryb "hub", który umożliwia sniffowanie pakietów atakującemu
    - Można zapobiegać poprzez
        - Statyczne tablice ARP (nie skaluje się)
        - Uruchomienie sticky MAC address. Zapisuje wszystkie aktualnie posiadane adresy MAC, żeby móc je załadować po reboocie.

### IP Network Layer

- Logical Addressing: IP
- Controls: ICMP, ARP, RARP
- Routing
    - static
        - Najbezpieczniejszy
        - Skalowanie to porażka
    - dynamic
        - Skalowalny, ale wymaga utworzenia polityk bezpieczeństwa
        - Automatyczne się aktualizuje
- Routing  Protocols:
    - IGP's (Interior Gateway Protocols)
        - RIP - Routing Information Protocol
        - IGRP - Interior Gateway Routing Protocol
        - EIGRP - Enhanced IGRP
        - OSPF - Open Shortest Path First
        - IS-IS - Intermediate System to Intermediate System
    - EGP's (Interior Gateway Protocols)
        - EGP - Exterior Gateway Protocol - nie jest już używany
        - BGP - Border Gateway Protocol - standard routingu w Internecie
- NAT - metoda na podłączenie wielu komputerów do Internetu używając jednego adresu IP
    - Przyczyny użycia
        - Niedobór adresów IP
        - Bezpieczeństwo
        - Łatwość z zarządzaniu i administacją sieci

## 3. Zagrożenia na protokoły sieciowe warstwy 4 i 7 modelu OSI 🏮

- S-HTTP - eksperymentalny protokół stworzony do stosowania z HTTP
- HTTPS - to HTTP przez SSL
    - SSL działa na warstwie 4 (Transportowej)
    - Wiadomości HTTP są opakowywane przez SSL
- DNS (Domain Name System)
    - Tłumaczy nazwy domen na adresy IP
    - DNS server - dostarcza nazwy domen do zamiany na adresy IP
    - DNS resolver - Próbuje przetłumaczyć domenę na IP. Jeśli nie jest w stanie przesyła prośbę do następnego serwera DNS
    - __Możliwe ataki__
        - HOSTS poisoning (static DNS) - atakujący jest wstanie umieścić fałszywe informację w pliku HOSTS (siedzi w nim adresów IP z ich nazwami domenowymi)
        - Caching DNS server attacks - umieszczenie fałszywych informacji w cache-u DNS-a, za pośrednictwem innego DNS. Dzięki temu atakujący może zwrócić fałszywy adres IP dla strony.
        - DNS lookup address changing - zmiana adresu IP serwera DNS użytkownika na wybrany przez atakującego
        - DNS query spoofing - Atakujący przechwytuje zapytanie do serwera DNS i podstawia adres własnego serwera
        - ![Spoofing](img/dnsspoof.png)
    - __Zabezpieczenia__
        - Instalacja HIDS i NIDS - możliwość wykrycia ataku
        - Ustawienie wielu serwerów DNS
        - Aktualizowanie systemu
        - Regularne przeglądanie logów DNS i DHCP

## 4. Sieci VLAN, charakterystyka, zasady działania

## 5. Rodzaje zapór ogniowych: Static Packet-filtering firewall, Stateful inspection firewall, Proxy firewall

- Static Packet-filtering firewall
    - Działa na warstwie 3 (Network Layer)
    - Router ACL's - listy dostępu
    - Nie sprawdza warstw 4-7 przez co nie może chronić przed atakami na konkretne aplikacje
    - Polityka Firewall-a
        - Domyślnie blokuje, przepuszczas w drodze wyjątku

- Stateful inspection firewall (Dynamic)
    - Layer 3-4
    - Sprawdza stan i kontekst ruchu sieciowego
    - Jest szybszy niż proxy, bo sprawdza tylko protokół TCP/IP, nie sprawdza danych
    - Nie przepisuje wszystkich pakietów

- Proxy firewall (Application-level gateway firewall)
    - Sprawdza pakiety na poziomie warstwy aplikacji
    - Analizuje polecenia aplikacji w środku pakietu
    - Nie zezwala na żadne bezpośrednie połączenie
    - Kopiuje pakiety z jednej sieci do drugiej (zmienia source i destination)
    - Niegatywnie pływa na wydajność sieci
    - Wspiera uwierzytelnienie na poziomie użytkownika

## 6. Architektura zapór ogniowych: I, II, III Tier

### Single tier

- Sieci prywatne na firewallem
- przydatne tylko dla generycznych ataków
- minimalny poziom ochrony

### Two tier I

- Firewall z trzema lub więcej interfejsami

### Two tier II

- Dwa połączone firewall-e
- DMZ (demilitarized zone) - system musi być dostępny zarówno z sieci prywatnej jak i Internetu

### Three tier

- Wiele podsieci pomiędzy siecią prywatną a Internetem, rozdzielone firewall-ami

![Firewall's tiers](img/firewall_tiers.png)

## 7. Systemy IDS i IPS: charakterystyka, metody detekcji, architektura. Honeypot

### IPS - Intrusion Preventing System

- Pełna kontrola pakietów
- umożliwia blokowanie ataków w czasie rzeczywistym
- Aktywne przechwytywanie i przekazywanie pakietów
- Kontrola dostępu i egzekwowanie polityki
- Zazwyczaj jest to urządzenie sieciowe
- Powstaje po połączenoi IDS-a z firewallem

### IDS - Intrusion Detection Systems

- Urządzenia/oprogramowanie do pasywnego monitoringu ruchu sieciowego w czasie rzeczywistym
- Network-based (N-IDS)
    - Pasywny monitoring i audyt przysyłanych pakietów
    - Analizują ruch w całej sieci
    - Potrafi wykrywać ataki z zewnątrz
    - Bazują na dopasowywaniu wzorców/sygnatur
        - Pattern/Signature Matching Method
            - Skanowanie pakietów w poszukiwaniu konkretnych sekwencji bitów
            - Identyfikacja znanych ataków
            - Wymaga regularnych aktualizacji sygnatur
        - Stateful Matching Method (śledzi pakiety w dłuższym okresie)
            - Skanuje cały strumień danych zamiast pojedynczych pakietów
            - Identyfikacja znanych ataków
            - Detekcja sygnatur w wielu pakietach
            - Wymaga regularnych aktualizacji sygnatur
        - Dekodowanie protokołów warstw wyższych
            - np. HTTP, FTP
            - pozwala na wstępną detekcję ataków pochodzących z tych warstw
    - Bazująca na anomaliach (Statistical/Anomaly-based)
        - Zdefiniowanie jak wygląda standardowy ruch sieciowy (wymaga bardzo dobrego zrozumienia jak wygląda standartowy ruch w sieci)
        - Możliwość wykrycia nieznanych wcześniej ataków i DoS
    - Protocol anomaly-based
        - szuka odchyleń o norm RFC
        - Możliwość wykrycia nieznanych wcześniej ataków
        - Może nie obsługiwać złożonych protokołów (SOAP, XML)
- Host-based (H-IDS)
    - Ograniczony do jednego hosta w sieci (np. serwera SQL, serwera aplikacji)
    - Analiza event logów, krytycznych plików systemowych i innych lógów
    - Sprawdzanie sygnatur plików (MD5, SHA-1) w celu wykrycia nieuprawnionych zmian
- Network Node IDS (NNIDS)
    - hybryda H-IDS i N-IDS
    - ochrona pojedynczego hosta połączona z analizą ruchu sieciowego skierowanego do tego konkretnego węzła sieci

### Sposoby reakcji systemu IDS

- wysłanie powiadomień
- zebranie dodatkowych informacji - po wykryciu próbu ataku system zbiera dodatkowe informację porzez aktywację dodatkowych reguł
- zmiana zachowania środowiskowego - zmiana konfiguracji firewall-a, routera. System stara się wyłączyć aktywność zarejestrowaną jako szkodliwa. Może np. zerwać połączenie z agresorem, zignorować ruch na określonych portach albo całkiem wyłączyć określone interfejsy sieciowe.

[Trochę więcej info co gdzie siedzi YT](https://www.youtube.com/watch?time_continue=2&v=O2Gz-v8WswQ&feature=emb_logo)
- Można zapiąć H-IDS na krytycznych elementach sieci a na reszcie N-IDS

### Honeypots

- _Honeypots_ to indywidualne komputery stworzone jako pułapka na atakującego
- _Honeynet_ to przynajmniej dwa połączone ze sobą honeypoty
- Wyglądają i zachowują się jak normalne komputery w sieci, ale nie zawierają żadnych wartościowych danych
- Administrator celowo konfiguruje honeypoty z dziurami bezpieczeństwa, żeby skłonić atakującego do ataku na nie
- Ma to na celu odciągnięcie atakującego od prawdziwego systemu, do czasu aż administrator nie zidentyfikuje intruza

## 8. VPN – charakterystyka, typy, protokoły

VPN - wirtualna sieć prywatna. Tworzy tunel między dwoma klientami, przez który przesyłane są pakiety. Tunel jest przezroczysty dla przesyłanych przez niego pakietów. Dane mogą być dodatkowo zaszyfrowane lub/i skompresowane.

### Typy VPN

- LAN-to-LAN (Sieć do sieci)
- Host-to-LAN (Pojedyncze urządzenie to sieci)
- Host-to-Host

![vpn](img/vpn.png)

### Przykłady

- PPTP (Point-to-Point Tunneling Protocol)
- L2TP (Layer 2 Tunneling Protocol)
- MPLS (Multi-Protocol Label Switching)
- GRE (Generic Routing Encapsulation)
- IPsec (Internet Protocol Security)
- SSH (Secure Shell)

### IPsec

Jest zestawem protokołów

Na warstwie Transportowej:

- AH (IP Authentication Header) - zapewnia uwierzytelnienie i integralność pakietów IP
- ESP (Encapsulating Security Payload) - zapewnia poufność danych poprzez szyfrowanie i opcjonalne uwierzytelnienie

Na warstwie Aplikacji:

- IKE (Internet Key Exchange) - Jego celem jest uwierzytelnienie obu stron komunikacji wobec siebie (za pomocą hasła, podpisu RSA, certyfikatu X.509). Następnie nawiązuje bezpieczny kanał nazywany ISAKMP SA (Security Assocation). Następnie uzgadnia klucze kryptograficzne oraz parametry IPsec. Ewentualnie może je renegocjować do jakiś czas.

Tryby pracy:

- Transport Mode:
    - nagłówki IP nie są szyfrowane
    - nagłówek IPsec jest wstawiany zaraz za nagłówkiem IP i szyfruje resztę pakietu
    - Atakujący nie wie o czym się rozmawia, ale wie kto z kim rozmawia
    - Tylko dla komunikacji host-to-host
- Tunnel Mode:
    - Szyfrowane jest wszystko (razem z nagłówkiem IP)
    - Dla wszystkich typów komunikacji
    - Całość jest enkapsulowana w pakiet ESP, na początek dokładany jest nagłowek IPn

### SSH

Działa pomiędzy warstwą aplikacji (HTTP, SMTP, NNTP) a warstwą transportową (TCP). Zwykle używany do zdalnego logowania z komputerem i wykonywanie poleceń. Obsługuje także tunelowanie, przekazywanie portów TCP i X11

- Wspiera negocjację między klientem a serwerem w celu ustalenia algorytmu kryptograficznego
    - Algorytmy z kluczem publicznym: RSA, Diffie-Hellman, DSA, Fortezza
    - Symetryczne: RC2, IDEA, DES, 3DES, AES
    - Funkcje haszujące: MD5, SHA

SSH zapobiega:

- przechwycenia danych przez atakującego
- manipulacji danych
- IP & DNS spoofing

## 9. Bezpieczeństwo sieci bezprzewodowych

## 10. Protokół SSL/TLS – charakterystyka, handshake

### SSL - Secure Sockets Layer & TLS - Trasport Layer Security

Protokół stworzony w celu zapewnienia prywatności i bezpieczeństwa danych w komunikacji internetowej. Podstawowym zastosowaniem jest szyfrowanie połączenia między aplikacją a serwerem. Może być także użyty do szyfrowania innych form komunikacji (email, VoIP).

TLS 1.0 jest takim SSL 3.1

TLS zapewnia integralność, uwierzytelnienie oraz szyfrowanie (poufność)

- Działa pomiędzy warstwą aplikacji (HTTP, SMTP, NNTP) a warstwą Transportową (TCP)
- Wspiera negocjację client-serwer i algorytmy kryptograficzne (RSA, Diffie-Hellman, DSA, RC2, AES, SHA)
- Działa w dwóch trybach - Application embedded (HTTPS) i SSL Tunel albo SSL VPN (OpenVPN)

#### SSL/TLS Handshake

Handshake zachodzi zawsze, kiedy użytkownik wchodzi na stronę internetową przez HTTPS. Zachodzi także dla każdej innej formy komunikacji wykorzystującej HTTPS (API, DNS)

- TLS wykorzystuje szyfrowanie asymetryczne (klucz prywatny i publiczny) w celu przesłania shared_key. Po wymianie klucza reszta komunikacji bazuje na kryptografi symetrycznej. Symetryczna bo jest sporo szybsza niż asynchroniczna

- [link YT](https://www.youtube.com/watch?v=cuR05y_2Gxc)
- [link](https://www.ssl.com/article/ssl-tls-handshake-overview/)

![img](img/tls1.png)
![img](img/tls2.png)

## 11. Siła szyfrowania – zasady, elementy składowe

## 12. Szyfry klasyczne: Podstawieniowe, Permutacyjne, Polialfabetyczne

## 13. Funkcje haszujące: cechy podstawowe, zastosowanie

## 14. Rodzaje funkcji haszujących: bez klucza (MD), z kluczem (MAC, HMAC) – charakterystyka, protokoły wykorzystujące funkcje haszujące

## 15. Kryptografia symetryczna: charakterystyka, przetwarzanie blokowe oraz strumieniowe, mieszanie oraz rozpraszanie, problem wymiany kluczy

## 16. Tryby pracy algorytmów symetrycznych: ECB, CBC, CFB,OFB, CTR

## 17. Algorytm DES: charakterystyka, opis rundy, s-bloki, tryby działania (TDES/3DES)

## 18. Algorytm AES: charakterystyka, opis rundy

## 19. Kryptografia asymetryczna: charakterystyka, problem faktoryzacji iloczynu liczb, problem logarytmu dyskretnego

## 20. Algorytm RSA: charakterystyka, zasada działania

## 21. Wymiana klucza Diffiego-Hellmana (DH): charakterystyka, protokół

## 22. Koncepcja krzywych eliptycznych (ECC)

## 23. Porównanie kryptografii symetrycznej z asymetryczną

## 24. Infrastruktura klucza publicznego PKI: charakterystyka, architektura, zasada działania, certyfikat klucza publicznego

## 25. HTTPS i PKI: charakterystyka, protokół

## 26. SSO i PKI: charakterystyka, protokół

## 27. Bezpieczna poczta – standard S/MIME: charakterystyka, zasada działania, protokół

## 28. System PGP: charakterystyka, zasada działania

## 29. Typy ataków kryptoanalitycznych

## 30. Ataki związane z kontrolą dostępu – Computing threats, Physical threats, Personnel/Social engineering threats

// Lecture0_access_control -> od 23 do 38

## 31. Koncepcja kontroli dostępu oparta o schemat AAA. Radius

//Lecture0_access_control -> od 38 do 44 i od 64
//Lecture02_telecom_network -> od 79

## 32. Jakościowe oraz ilościowe metody analizy ryzyka

## 33. Rodzaje kontroli dostępów: Known, Has, Is

//Lecture0_access_control -> od 48 do 51

## 34. Modele kontroli dostępu: DAC, MAC, HRU, ACL, RBAC  

//Lecture0_access_control -> od 51

## 35. Ataki SQL Injection

## 36. Ataki XSS

## 37. Obsługa danych z niezaufanego źródła – aplikacje WEB

## 38. Obsługa Złożonych danych - aplikacje WEB
