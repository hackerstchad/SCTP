# SCTP_TECHNOLOGY

<img width="640" height="480" alt="images" src="https://github.com/user-attachments/assets/9d32a745-7f58-49e0-9b13-9f607ae96792" />


## Présentation

**SCTP_TECHNOLOGY** est une application éducative avancée écrite en Python (interface [`tkinter`](sctp_technology.py:1)) dédiée au protocole **SCTP (Stream Control Transmission Protocol)** définie dans la RFC 4960.

---

## Démarrage rapide

```bash
# 1. Cloner ou créer le dossier
mkdir sctp_technology && cd sctp_technology

# 2. Lancer l'application
python sctp_technology.py

# 3. (Optionnel) installer les dépendances
pip install -r requirements.txt
```

---

##  Fichiers

| Fichier | Description |
|---------|-------------|
| [`sctp_technology.py`](sctp_technology.py) | Application principale (1000+ lignes) |
| [`requirements.txt`](requirements.txt) | Dépendances Python |
| [`README.md`](README.md) | Documentation complète |

---

##  Qu'est-ce que SCTP ?

SCTP est un protocole de transport de couche 4 (comme TCP et UDP) standardisé par l'IETF dans la [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960).

### Caractéristiques principales

| Caractéristique | Description |
|-----------------|-------------|
| **Multi-homing** | Une association peut utiliser plusieurs adresses IP par extrémité pour la redondance. |
| **Multi-streaming** | Plusieurs flux indépendants dans une seule association ; un blocage n'affecte pas les autres. |
| **Livraison ordonnée par stream** | Chaque stream garantit l'ordre, mais les streams sont indépendants. |
| **Orienté message** | Préserve les frontières des messages (contrairement au TCP orienté flux d'octets). |
| **Contrôle de congestion** | Similaire à TCP avec slow-start, congestion window, SACK. |
| **Robustesse** | Heartbeats, retransmissions, checksum CRC32c, vtags anti-ambiguïté. |

### Comparaison TCP / UDP / SCTP

| Propriété | TCP | UDP | SCTP |
|-----------|-----|-----|------|
| Orienté connexion | Oui | Non | Oui |
| Fiabilité | Oui | Non | Oui |
| Ordre | Oui (global) | Non | Oui (par stream) |
| Multi-homing | Non | Non | Oui |
| Multi-streaming | Non | Non | Oui |
| Orienté message | Non | Non | Oui |

---

##  Ressources et liens officiels

### RFCs

- [RFC 4960 - SCTP](https://datatracker.ietf.org/doc/html/rfc4960)
- [RFC 3286 - Introduction to SCTP](https://datatracker.ietf.org/doc/html/rfc3286)
- [RFC 3758 - SCTP Partial Reliability Extension](https://datatracker.ietf.org/doc/html/rfc3758)
- [RFC 5061 - SCTP Dynamic Address Reconfiguration](https://datatracker.ietf.org/doc/html/rfc5061)
- [RFC 6525 - SCTP Stream Reconfiguration](https://datatracker.ietf.org/doc/html/rfc6525)

### Articles et tutoriels

- [Wikipedia - SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol)
- [Network Sorcery - SCTP](http://www.networksorcery.com/enp/protocol/sctp.htm)
- [IBM Developer - SCTP](https://developer.ibm.com/tutorials/l-sctp/)

### Outils réseau

```bash
# Sur Linux, vérifier le support SCTP du noyau
lsmod | grep sctp

# Installer les outils utilisateur SCTP (Debian/Ubuntu)
sudo apt-get install libsctp-dev lksctp-tools

# Capturer du trafic SCTP avec tcpdump
sudo tcpdump -i any -nn -s 0 -w sctp_capture.pcap sctp

# Analyser avec Wireshark
wireshark sctp_capture.pcap

# Envoyer des paquets SCTP avec nmap (NSE)
nmap -sY -p 5060 <cible>

# Tester une socket SCTP avec Python (module externe `sctp`)
pip install sctp
```

### Support noyau Linux

```bash
# Vérifier le module SCTP
modinfo sctp

# Charger le module
sudo modprobe sctp

# Vérifier les sockets SCTP en écoute
ss -S
```

---

## 🛠️ Architecture du script

L'application [`sctp_technology.py`](sctp_technology.py) est structurée autour de plusieurs classes Tkinter :

- `SCTPTechnologyApp` : fenêtre principale et gestion des onglets
- `SCTPConnectionSimulator` : simulation d'association SCTP
- `SCTP3DVisualizer` : visualisation 3D simplifiée via Canvas
- `SCTPPacketEditor` : construction et décodage de paquets
- `SCTPCalculator` : calculs de CRC32c, VTAG, TSN, etc.

---

##  Commandes et utilisation

### Lancer l'application

```bash
python sctp_technology.py
```

### Onglets disponibles

1. **Accueil** : introduction et statistiques
2. **Simulateur** : crée une association, envoie des DATA chunks, observe les TSN/SID/SSN
3. **Visualisation 3D** : représentation graphique des streams et transmissions
4. **Éditeur de paquets** : assemble un paquet SCTP et décode ses chunks
5. **Calculateur** : CRC32c, verification tag, séquence numbers
6. **Apprentissage** : questions/réponses interactives sur SCTP
7. **Ressources** : liens RFC et commandes réseau

---

##  Exemple de simulation

1. Ouvrir l'onglet **Simulateur**.
2. Entrer les IP locales et distantes.
3. Cliquer sur **Initier Association**.
4. Envoyer des messages ; observer les chunks DATA avec TSN, Stream ID, SSN.
5. Basculer dans l'onglet **Visualisation 3D** pour voir les flux.

---

##  Tests

```bash
# Vérifier la syntaxe
python -m py_compile sctp_technology.py

# Lancer (tests manuels via l'interface)
python sctp_technology.py
```


##  Licence

Projet éducatif. Libre à usage personnel et pédagogique.
