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
    - Jakie zasoby maja być dostępne
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

## 2. Zagrożenia na protokoły sieciowe warstwy 2 i 3 modelu OSI

## 3. Zagrożenia na protokoły sieciowe warstwy 4 i 7 modelu OSI

## 4. Sieci VLAN, charakterystyka, zasady działania

## 5. Rodzaje zapór ogniowych: Static Packet-filtering firewall, Stateful inspection firewall, Proxy firewall

## 6. Architektura zapór ogniowych: I, II, III Tier

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

## 8. VPN – charakterystyka, typy, protokoły

## 9. Bezpieczeństwo sieci bezprzewodowych

## 10. Protokół SSL/TLS – charakterystyka, handshake

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

## 32. Jakościowe oraz ilościowe metody analizy ryzyka

## 33. Rodzaje kontroli dostępów: Known, Has, Is

//Lecture0_access_control -> od 48 do 51

## 34. Modele kontroli dostępu: DAC, MAC, HRU, ACL, RBAC  

//Lecture0_access_control -> od 51

## 35. Ataki SQL Injection

## 36. Ataki XSS

## 37. Obsługa danych z niezaufanego źródła – aplikacje WEB

## 38. Obsługa Złożonych danych - aplikacje WEB
