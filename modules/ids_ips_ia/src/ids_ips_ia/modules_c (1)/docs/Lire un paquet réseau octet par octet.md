# Lire un paquet réseau octet par octet

Un paquet est une rangée d'octets. Chaque couche (Ethernet, IP, TCP…) est une boîte posée dans la précédente, avec une étiquette qui dit où commence la suivante. Ton parseur C est un doigt qui avance sur cette rangée. Couleurs partout : Ethernet IPv4 TCP reste

## 1. Le paquet en un coup d'œil

Le nombre à gauche est **l'octet où commence la boîte**. On compte à partir de 0 : un paquet de 60 octets va de 0 à 59. Ce paquet est un SYN sans données : les octets 54 à 59 sont du **bourrage** (padding) ajouté par Ethernet pour atteindre 60 octets minimum.

## 2. Lire des octets

Un octet = 8 bits = 2 chiffres hexadécimaux (`0x45`, `0xBB`…). Pour un nombre sur 2 octets, comme un port, l'octet de **poids fort arrive en premier** (big endian).

| Octets | Calcul | Valeur |
| --- | --- | --- |
| `01 BB` | 0x01 × 256 + 0xBB (187) | 443 |
| `C7 38` | 0xC7 (199) × 256 + 0x38 (56) | 51000 |
| `00 28` | 0 × 256 + 40 | 40 |

En C : `(p[i] << 8) | p[i+1]`. Le `<< 8` pousse l'octet fort 8 bits vers la gauche, le `|` colle le second à côté.

## 3. Ethernet et IPv4, champ par champ

Deux nombres par champ : **à gauche** la position dans le paquet (celle que tu utilises), **dans la boîte** la position dans l'en-tête IPv4 (celle de la documentation). Le lien : **position absolue = 14 + décalage**. Le protocole est à 14 + 9 = 23, l'IP source à 14 + 12 = 26.

## 4. L'IHL : comment le lire

1. Prends l'octet 14 : ici `0x45`, soit `0100 0101` en binaire.
2. **Moitié basse (IHL)** : `octet & 0x0F`. Le ET binaire avec `0000 1111` garde les 4 bits du bas et met ceux du haut à 0 : `0100 0101` ET `0000 1111` = `0000 0101` = 5.
3. **Moitié haute (version)** : `octet >> 4` pousse tout de 4 rangs vers la droite : `0000 0100` = 4.
4. **Taille en octets** : `IHL × 4`, car l'IHL compte en groupes de 4 octets. 5 × 4 = 20.

| IHL | En-tête IP | Début du TCP | Verdict |
| --- | --- | --- | --- |
| 0 à 4 | moins de 20 | - | invalide, on rejette |
| 5 | 20 octets | 14 + 20 = 34 | cas normal |
| 6 | 24 octets | 14 + 24 = 38 | options IP présentes |
| 15 | 60 octets | 14 + 60 = 74 | maximum |

Même technique pour TCP : l'octet 46 vaut `0x50`, donc `0x50 >> 4` = 5, soit 5 × 4 = 20 octets d'en-tête TCP.

## 5. Où commence le TCP, et ce qu'il contient

Formule : **début du TCP = 14 + IHL × 4**. Les positions ci-dessus supposent IHL = 5 ; avec IHL = 6, tout glisse de 4 octets. Les **flags** tiennent dans un seul octet, un bit par flag :

Pour tester le SYN : `flags & 0x02` est non nul si le bit est levé. Un octet `0x12` = `0x10` + `0x02` = ACK + SYN. En coral, les 4 flags les plus utiles.

## 6. Exemple complet : un SYN réel

Connexion de 192.168.1.10:51000 vers 10.0.0.9:443, 60 octets (hexadécimal, 16 octets par ligne) :

```
0000  00 1A 2B 3C 4D 5E 00 11 22 33 44 55 08 00 45 00
0010  00 28 1C 46 40 00 40 06 00 00 C0 A8 01 0A 0A 00
0020  00 09 C7 38 01 BB 00 00 00 01 00 00 00 00 50 02
0030  FF FF 00 00 00 00 00 00 00 00 00 00
```

| Où | Octets | Lecture |
| --- | --- | --- |
| 12-13 | `08 00` | type 0x0800 : IPv4 |
| 14 | `45` | version 4, IHL 5 : en-tête IP de 20 octets, TCP à l'octet 34 |
| 16-17 | `00 28` | longueur IP = 40, donc fin réelle = 14 + 40 = 54 : le reste est du bourrage |
| 23 | `06` | protocole 6 : TCP |
| 26-29 | `C0 A8 01 0A` | 192.168.1.10 (un octet par nombre) |
| 30-33 | `0A 00 00 09` | 10.0.0.9 |
| 34-35 | `C7 38` | port source 51000 |
| 36-37 | `01 BB` | port destination 443 |
| 46 | `50` | 0x50 >> 4 = 5 : en-tête TCP de 20 octets |
| 47 | `02` | 0x02 & 0x02 non nul : SYN |

## 7. Les vérifications, dans l'ordre

1. **Avant chaque lecture**, vérifie qu'il reste assez d'octets : 14 pour Ethernet, puis 14 + 20 pour l'IP minimale.
2. **Type Ethernet** : `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP. Si `0x8100` (VLAN), tout glisse de 4 octets.
3. **Version = 4** et **IHL ≥ 5**, puis 14 + IHL × 4 ≤ longueur capturée.
4. **Longueur IP** (octets 16-17) : ≥ IHL × 4 et ≤ longueur capturée − 14. Fin réelle = 14 + longueur IP ; au-delà, c'est du bourrage.
5. **Fragments** : le décalage de fragment (13 bits bas des octets 20-21) doit valoir 0 pour lire des ports. Sinon, pas d'en-tête TCP/UDP ici.
6. **TCP** : décalage de données ≥ 5, et IHL × 4 + décalage × 4 ≤ longueur IP.
7. **Protocole inconnu** : remplis la fiche, compte-le, ne le jette pas en silence (un tunnel est une façon d'esquiver un IDS).

## 8. À toi de jouer

1\. L'octet 14 vaut 0x47. Version, IHL, début du TCP ?

Version 4, IHL 7, en-tête de 28 octets, donc le TCP commence à 14 + 28 = **42**.

2\. Les octets 36-37 valent 01 F6. Quel port ?

0x01 × 256 + 0xF6 (246) = **502**.

3\. L'octet de flags vaut 0x12. Quels flags ?

0x12 = 0x10 + 0x02 : **ACK + SYN**, la réponse d'un serveur à une demande de connexion.

4\. L'octet 14 vaut 0x43. Que fais-tu ?

IHL = 3, donc moins de 20 octets : l'en-tête est invalide, on **rejette** le paquet.