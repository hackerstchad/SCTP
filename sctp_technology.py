#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCTP_TECHNOLOGY
===============
Application éducative avancée expliquant le protocole SCTP (Stream Control Transmission Protocol, RFC 4960).
Fonctionnalités :
- Interface Tkinter moderne et stylisée (plus de 1000 lignes)
- Visualisation 3D simplifiée du handshake SCTP (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK)
- Visualisation de la structure d'un chunk SCTP
- Simulation de multi-homing et multi-streaming
- Outil d'analyse de paquets SCTP (affichage éducatif)
- Générateur de commandes Linux pour inspecter/manipuler SCTP
- README intégré dans l'onglet "Documentation"

Auteur : CodePal
Licence : MIT
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import math
import random
import time
import threading
import socket
import struct
import os
import sys

# ============================================================
# CONSTANTES SCTP
# ============================================================

SCTP_PORT_DEFAULT = 5061
SCTP_COMMON_HEADER_LEN = 12
SCTP_CHUNK_TYPES = {
    0: "DATA",
    1: "INIT",
    2: "INIT-ACK",
    3: "SACK",
    4: "HEARTBEAT",
    5: "HEARTBEAT-ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN-ACK",
    9: "ERROR",
    10: "COOKIE-ECHO",
    11: "COOKIE-ACK",
    14: "SHUTDOWN-COMPLETE",
    15: "AUTH",
    62: "I-DATA",
    126: "FORWARD-TSN",
    192: "ASCONF",
    193: "ASCONF-ACK",
    198: "RE-CONFIG",
}

CHUNK_COLORS = {
    "INIT": "#3498db",
    "INIT-ACK": "#2ecc71",
    "COOKIE-ECHO": "#f39c12",
    "COOKIE-ACK": "#9b59b6",
    "DATA": "#e74c3c",
    "SACK": "#1abc9c",
    "HEARTBEAT": "#34495e",
    "ABORT": "#c0392b",
    "SHUTDOWN": "#7f8c8d",
    "UNKNOWN": "#95a5a6",
}

# ============================================================
# STYLES / THEME
# ============================================================

BG_COLOR = "#0f172a"
CARD_BG = "#1e293b"
ACCENT = "#38bdf8"
TEXT_COLOR = "#e2e8f0"
SECONDARY_TEXT = "#94a3b8"
SUCCESS = "#4ade80"
WARNING = "#fbbf24"
DANGER = "#f87171"

FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"

# ============================================================
# DONNÉES ÉDUCATIVES SCTP
# ============================================================

SCTP_CONCEPTS = {
    "Définition": (
        "SCTP (Stream Control Transmission Protocol) est un protocole de transport fiable, orienté connexion, "
        "normalisé dans la RFC 4960. Il combine des caractéristiques de TCP (fiabilité, contrôle de congestion, "
        "ordre) et d'UDP (message-oriented, support du multi-homing et du multi-streaming)."
    ),
    "Multi-streaming": (
        "SCTP permet d'ouvrir plusieurs flux (streams) au sein d'une même association. "
        "Si un paquet est perdu sur un flux, les autres flux peuvent continuer à livrer leurs données sans blocage. "
        "Cela résout le problème de Head-of-Line Blocking de TCP."
    ),
    "Multi-homing": (
        "Une association SCTP peut lier plusieurs adresses IP à chaque extrémité. "
        "En cas de défaillance du chemin principal, SCTP bascule automatiquement sur un chemin secondaire "
        "sans rompre l'association."
    ),
    "4-way handshake": (
        "Contrairement à TCP (3-way handshake), SCTP établit une connexion en 4 étapes :\n"
        "1. INIT (client -> serveur)\n"
        "2. INIT-ACK (serveur -> client)\n"
        "3. COOKIE-ECHO (client -> serveur)\n"
        "4. COOKIE-ACK (serveur -> client)\n"
        "Le cookie anti-dénier protège contre les attaques SYN flood."
    ),
    "Chunks": (
        "Les données SCTP sont transportées sous forme de chunks (morceaux). Chaque chunk a un type, des flags, "
        "une longueur et une valeur. Les types principaux sont DATA, INIT, INIT-ACK, SACK, HEARTBEAT, ABORT, "
        "SHUTDOWN, COOKIE-ECHO, COOKIE-ACK."
    ),
    "SACK": (
        "Selective Acknowledgement (SACK) permet au récepteur d'accuser réception sélectivement des paquets reçus "
        "et de signaler les trous dans la séquence. Cela améliore la retransmission par rapport à TCP classique."
    ),
    "Path MTU discovery": (
        "SCTP découvre automatiquement la MTU du chemin pour éviter la fragmentation IP, améliorant ainsi "
        "les performances et la fiabilité."
    ),
}

SCTP_PACKET_STRUCTURE = """
+--------------------------------------------------+
|           SCTP COMMON HEADER (12 octets)         |
+--------------------------------------------------+
|  Source Port (16 bits)  |  Destination Port (16)  |
+--------------------------------------------------+
|              Verification Tag (32 bits)           |
+--------------------------------------------------+
|                Checksum (32 bits)                 |
+--------------------------------------------------+
|  Chunk Type (8) | Flags (8) | Chunk Length (16)   |
+--------------------------------------------------+
|                 Chunk Value (variable)            |
+--------------------------------------------------+
"""

COMMANDS = [
    ("Lister les associations SCTP", "ss -tan | grep sctp"),
    ("Statistiques SCTP (Linux)", "cat /proc/net/sctp/assocs"),
    ("Modules SCTP chargés", "lsmod | grep sctp"),
    ("Activer SCTP dans le noyau", "sudo modprobe sctp"),
    ("Capturer du trafic SCTP", "sudo tcpdump -i any sctp -w sctp_capture.pcap"),
    ("Infos détaillées SCTP", "cat /proc/net/sctp/snmp"),
    ("Tester un port SCTP avec nmap", "nmap -sY -p 5061 <cible>"),
    ("Créer une socket SCTP (Python)", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)"),
]

RESOURCES = [
    ("RFC 4960 - SCTP", "https://tools.ietf.org/html/rfc4960"),
    ("RFC 3286 - SCTP intro", "https://tools.ietf.org/html/rfc3286"),
    ("RFC 5061 - SCTP Dynamic Address Reconfiguration", "https://tools.ietf.org/html/rfc5061"),
    ("RFC 6525 - SCTP Stream Reconfiguration", "https://tools.ietf.org/html/rfc6525"),
    ("Wikipedia SCTP", "https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol"),
    ("Linux Kernel SCTP", "https://wiki.linuxfoundation.org/networking/sctp"),
    ("Wireshark SCTP Wiki", "https://wiki.wireshark.org/SCTP"),
    ("IETF TSVWG", "https://datatracker.ietf.org/wg/tsvwg/documents/"),
]

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================

def compute_adler32(data: bytes) -> int:
    """Calcule un checksum Adler-32 (style SCTP/RFC 3309 historique)."""
    a = 1
    b = 0
    MOD_ADLER = 65521
    for byte in data:
        a = (a + byte) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    return (b << 16) | a

def format_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)

def chunk_type_name(chunk_type: int) -> str:
    return SCTP_CHUNK_TYPES.get(chunk_type, f"UNKNOWN({chunk_type})")

def chunk_color(name: str) -> str:
    return CHUNK_COLORS.get(name, CHUNK_COLORS["UNKNOWN"])

# ============================================================
# SIMULATION DE PAQUET SCTP
# ============================================================

class SCTPPacketSimulator:
    """Génère des paquets SCTP éducatifs en bytes."""

    def __init__(self, src_port: int = 12345, dst_port: int = SCTP_PORT_DEFAULT, vtag: int = 0x12345678):
        self.src_port = src_port
        self.dst_port = dst_port
        self.vtag = vtag

    def build_common_header(self) -> bytes:
        header = struct.pack(
            "!HHII",
            self.src_port,
            self.dst_port,
            self.vtag,
            0,  # checksum placeholder
        )
        return header

    def build_init_chunk(self, init_tag: int, num_outbound_streams: int = 10, num_inbound_streams: int = 10) -> bytes:
        chunk_type = 1
        flags = 0
        initiate_tag = struct.pack("!I", init_tag)
        a_rwnd = struct.pack("!I", 65535)
        out_streams = struct.pack("!H", num_outbound_streams)
        in_streams = struct.pack("!H", num_inbound_streams)
        initial_tsn = struct.pack("!I", random.randint(1, 0xFFFFFFFF))
        value = initiate_tag + a_rwnd + out_streams + in_streams + initial_tsn
        length = 4 + len(value)
        chunk_header = struct.pack("!BBH", chunk_type, flags, length)
        padding = (4 - (length % 4)) % 4
        return chunk_header + value + b"\x00" * padding

    def build_cookie_echo_chunk(self, cookie: bytes) -> bytes:
        chunk_type = 10
        flags = 0
        length = 4 + len(cookie)
        chunk_header = struct.pack("!BBH", chunk_type, flags, length)
        padding = (4 - (length % 4)) % 4
        return chunk_header + cookie + b"\x00" * padding

    def build_data_chunk(self, tsn: int, stream_id: int, seq: int, payload: bytes) -> bytes:
        chunk_type = 0
        flags = 0x03  # B+E bits (message complet dans un seul chunk)
        tsn_bytes = struct.pack("!I", tsn)
        sid_bytes = struct.pack("!H", stream_id)
        ssn_bytes = struct.pack("!H", seq)
        ppid_bytes = struct.pack("!I", 0)
        value = tsn_bytes + sid_bytes + ssn_bytes + ppid_bytes + payload
        length = 4 + len(value)
        chunk_header = struct.pack("!BBH", chunk_type, flags, length)
        padding = (4 - (length % 4)) % 4
        return chunk_header + value + b"\x00" * padding

    def build_packet(self, chunks: list) -> bytes:
        payload = b"".join(chunks)
        header = self.build_common_header()
        packet = header + payload
        # Insert fake checksum (Adler-32 sur tout le paquet)
        cksum = compute_adler32(packet)
        packet = packet[:8] + struct.pack("!I", cksum)
        return packet

    def parse_packet(self, packet: bytes) -> dict:
        if len(packet) < SCTP_COMMON_HEADER_LEN:
            return {"error": "Paquet trop court"}
        src_port, dst_port, vtag, cksum = struct.unpack("!HHII", packet[:12])
        result = {
            "src_port": src_port,
            "dst_port": dst_port,
            "verification_tag": f"0x{vtag:08x}",
            "checksum": f"0x{cksum:08x}",
            "chunks": [],
        }
        offset = 12
        while offset + 4 <= len(packet):
            chunk_type, flags, length = struct.unpack("!BBH", packet[offset:offset + 4])
            name = chunk_type_name(chunk_type)
            value = packet[offset + 4:offset + length]
            result["chunks"].append({
                "type": chunk_type,
                "name": name,
                "flags": flags,
                "length": length,
                "value": value,
                "color": chunk_color(name),
            })
            padded_length = length + ((4 - (length % 4)) % 4)
            offset += padded_length
        return result

# ============================================================
# WIDGET DE VISUALISATION 3D SIMPLIFIÉE
# ============================================================

class Pseudo3DCanvas(tk.Canvas):
    """Canvas simulant une scène 3D avec chunks SCTP en mouvement."""

    def __init__(self, parent, width=800, height=500, **kwargs):
        super().__init__(parent, width=width, height=height, bg=BG_COLOR, highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.objects = []
        self.running = True
        self.angle = 0
        self.draw_axes()
        self.after(33, self.animate)

    def project_3d(self, x: float, y: float, z: float) -> tuple:
        """Projection orthographique/isométrique simple."""
        scale = 0.8
        cx, cy = self.width // 2, self.height // 2 + 50
        # Rotation autour de l'axe Y
        theta = math.radians(30 + self.angle * 0.2)
        x_rot = x * math.cos(theta) - z * math.sin(theta)
        z_rot = x * math.sin(theta) + z * math.cos(theta)
        # Rotation autour de l'axe X
        phi = math.radians(20)
        y_rot = y * math.cos(phi) - z_rot * math.sin(phi)
        z_final = y * math.sin(phi) + z_rot * math.cos(phi)
        px = cx + x_rot * scale
        py = cy - y_rot * scale + z_final * 0.15
        return px, py, z_final

    def draw_axes(self):
        self.delete("axis")
        origin = self.project_3d(0, 0, 0)
        x_end = self.project_3d(200, 0, 0)
        y_end = self.project_3d(0, 120, 0)
        z_end = self.project_3d(0, 0, 200)
        self.create_line(origin[0], origin[1], x_end[0], x_end[1], fill="#ef4444", width=2, tags="axis")
        self.create_line(origin[0], origin[1], y_end[0], y_end[1], fill="#22c55e", width=2, tags="axis")
        self.create_line(origin[0], origin[1], z_end[0], z_end[1], fill="#3b82f6", width=2, tags="axis")
        self.create_text(x_end[0] + 10, x_end[1], text="X (Streams)", fill="#ef4444", tags="axis")
        self.create_text(y_end[0], y_end[1] - 10, text="Y (Hosts)", fill="#22c55e", tags="axis")
        self.create_text(z_end[0], z_end[1], text="Z (Time)", fill="#3b82f6", tags="axis")

    def add_chunk_cube(self, x: float, y: float, z: float, color: str, label: str):
        size = 25
        points = [
            (x - size, y - size, z - size),
            (x + size, y - size, z - size),
            (x + size, y + size, z - size),
            (x - size, y + size, z - size),
            (x - size, y - size, z + size),
            (x + size, y - size, z + size),
            (x + size, y + size, z + size),
            (x - size, y + size, z + size),
        ]
        projected = [self.project_3d(*p) for p in points]
        faces = [
            (0, 1, 2, 3),
            (4, 5, 6, 7),
            (0, 1, 5, 4),
            (2, 3, 7, 6),
            (1, 2, 6, 5),
            (0, 3, 7, 4),
        ]
        avg_z = [sum(projected[i][2] for i in face) / 4 for face in faces]
        sorted_faces = sorted(zip(faces, avg_z), key=lambda t: t[1], reverse=True)
        item_ids = []
        for face, _ in sorted_faces:
            coords = []
            for i in face:
                coords.extend([projected[i][0], projected[i][1]])
            poly = self.create_polygon(coords, fill=color, outline="#0f172a", width=2, stipple="gray50")
            item_ids.append(poly)
        cx = sum(p[0] for p in projected) / 8
        cy = sum(p[1] for p in projected) / 8
        txt = self.create_text(cx, cy, text=label, fill="white", font=(FONT_FAMILY, 8, "bold"))
        item_ids.append(txt)
        self.objects.append({
            "ids": item_ids,
            "x": x,
            "y": y,
            "z": z,
            "color": color,
            "label": label,
            "created": time.time(),
        })

    def animate(self):
        if not self.running:
            return
        self.angle += 1
        self.delete("all")
        self.draw_axes()
        now = time.time()
        for obj in list(self.objects):
            if now - obj["created"] > 8:
                self.objects.remove(obj)
                continue
            obj["z"] += 2
            self.add_chunk_cube(obj["x"], obj["y"], obj["z"], obj["color"], obj["label"])
        self.after(33, self.animate)

    def stop(self):
        self.running = False

# ============================================================
# ONGLET : VUE D'ENSEMBLE
# ============================================================

class OverviewTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(style="Card.TFrame")
        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(
            self,
            text="SCTP - Stream Control Transmission Protocol",
            font=(FONT_FAMILY, 22, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        )
        title.pack(pady=(20, 10))

        subtitle = tk.Label(
            self,
            text="RFC 4960 | Fiabilité, multi-streaming, multi-homing, message-oriented",
            font=(FONT_FAMILY, 12),
            fg=SECONDARY_TEXT,
            bg=CARD_BG,
        )
        subtitle.pack(pady=(0, 20))

        content = tk.Frame(self, bg=CARD_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)

        for idx, (concept, text) in enumerate(SCTP_CONCEPTS.items()):
            row = idx // 2
            col = idx % 2
            card = tk.Frame(content, bg=BG_COLOR, bd=1, relief=tk.RIDGE)
            card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
            card.grid_columnconfigure(0, weight=1)
            lbl_title = tk.Label(
                card,
                text=concept,
                font=(FONT_FAMILY, 13, "bold"),
                fg=ACCENT,
                bg=BG_COLOR,
            )
            lbl_title.pack(anchor="w", padx=15, pady=(10, 5))
            lbl_text = tk.Label(
                card,
                text=text,
                font=(FONT_FAMILY, 10),
                fg=TEXT_COLOR,
                bg=BG_COLOR,
                wraplength=360,
                justify=tk.LEFT,
            )
            lbl_text.pack(anchor="w", padx=15, pady=(0, 15))

        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)

# ============================================================
# ONGLET : HANDSHAKE 3D
# ============================================================

class HandshakeTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.step_index = 0
        self.handshake_steps = [
            ("INIT", "Client envoie INIT au serveur", -200, -80, "#3498db"),
            ("INIT-ACK", "Serveur répond INIT-ACK", 200, -80, "#2ecc71"),
            ("COOKIE-ECHO", "Client renvoie le cookie", -200, 80, "#f39c12"),
            ("COOKIE-ACK", "Serveur accuse réception", 200, 80, "#9b59b6"),
        ]
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Visualisation 3D du handshake SCTP (4-way)",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        btn_frame = tk.Frame(header, bg=CARD_BG)
        btn_frame.pack(side=tk.RIGHT, padx=20)

        self.btn_start = tk.Button(
            btn_frame,
            text="▶ Démarrer la simulation",
            command=self.start_simulation,
            bg=SUCCESS,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)

        self.btn_reset = tk.Button(
            btn_frame,
            text="↺ Réinitialiser",
            command=self.reset_simulation,
            bg=WARNING,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        )
        self.btn_reset.pack(side=tk.LEFT, padx=5)

        self.canvas = Pseudo3DCanvas(self, width=900, height=500)
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.log = scrolledtext.ScrolledText(
            self,
            height=8,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.log.pack(fill=tk.X, padx=20, pady=10)
        self.log.insert(tk.END, "Cliquez sur 'Démarrer la simulation' pour voir le handshake SCTP en 3D.\n")

    def start_simulation(self):
        self.step_index = 0
        self.canvas.objects.clear()
        self.log.delete("1.0", tk.END)
        self.log.insert(tk.END, "Simulation du handshake SCTP démarrée.\n")
        self.run_step()

    def run_step(self):
        if self.step_index >= len(self.handshake_steps):
            self.log.insert(tk.END, "Association SCTP établie avec succès !\n")
            return
        name, desc, x, y, color = self.handshake_steps[self.step_index]
        self.canvas.add_chunk_cube(x, y, -200, color, name)
        self.log.insert(tk.END, f"[{name}] {desc}\n")
        self.log.see(tk.END)
        self.step_index += 1
        self.after(1500, self.run_step)

    def reset_simulation(self):
        self.canvas.objects.clear()
        self.log.delete("1.0", tk.END)
        self.log.insert(tk.END, "Simulation réinitialisée.\n")

# ============================================================
# ONGLET : STRUCTURE DU PAQUET
# ============================================================

class PacketStructureTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.sim = SCTPPacketSimulator()
        self.create_widgets()
        self.generate_packet()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Structure d'un paquet SCTP (RFC 4960)",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        btn = tk.Button(
            header,
            text="Générer un nouveau paquet",
            command=self.generate_packet,
            bg=ACCENT,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        )
        btn.pack(side=tk.RIGHT, padx=20)

        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=CARD_BG)
        paned.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        left = tk.Frame(paned, bg=BG_COLOR)
        paned.add(left, width=450)

        self.structure_text = tk.Text(
            left,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_MONO, 10),
            wrap=tk.NONE,
            insertbackground=ACCENT,
        )
        self.structure_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.structure_text.insert(tk.END, SCTP_PACKET_STRUCTURE)

        right = tk.Frame(paned, bg=BG_COLOR)
        paned.add(right, width=450)

        self.hex_text = scrolledtext.ScrolledText(
            right,
            bg=BG_COLOR,
            fg=SUCCESS,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.parse_text = scrolledtext.ScrolledText(
            right,
            bg=BG_COLOR,
            fg=WARNING,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.parse_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def generate_packet(self):
        init_chunk = self.sim.build_init_chunk(init_tag=0xABCDEF01)
        cookie = os.urandom(32)
        cookie_chunk = self.sim.build_cookie_echo_chunk(cookie)
        payload = b"Hello SCTP!"
        data_chunk = self.sim.build_data_chunk(tsn=1, stream_id=5, seq=0, payload=payload)
        packet = self.sim.build_packet([init_chunk, cookie_chunk, data_chunk])

        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert(tk.END, "Paquet SCTP généré (hex dump 16 octets/ligne):\n\n")
        for i in range(0, len(packet), 16):
            chunk = packet[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self.hex_text.insert(tk.END, f"{i:04x}  {hex_part:<48}  {ascii_part}\n")

        self.parse_text.delete("1.0", tk.END)
        parsed = self.sim.parse_packet(packet)
        if "error" in parsed:
            self.parse_text.insert(tk.END, f"Erreur: {parsed['error']}\n")
            return
        self.parse_text.insert(tk.END, "=== Parsing du paquet SCTP ===\n")
        self.parse_text.insert(tk.END, f"Source Port      : {parsed['src_port']}\n")
        self.parse_text.insert(tk.END, f"Destination Port : {parsed['dst_port']}\n")
        self.parse_text.insert(tk.END, f"Verification Tag : {parsed['verification_tag']}\n")
        self.parse_text.insert(tk.END, f"Checksum         : {parsed['checksum']}\n")
        self.parse_text.insert(tk.END, f"Nombre de chunks : {len(parsed['chunks'])}\n\n")
        for idx, chunk in enumerate(parsed["chunks"], 1):
            self.parse_text.insert(tk.END, f"Chunk #{idx}\n")
            self.parse_text.insert(tk.END, f"  Type   : {chunk['type']} ({chunk['name']})\n")
            self.parse_text.insert(tk.END, f"  Flags  : 0x{chunk['flags']:02x}\n")
            self.parse_text.insert(tk.END, f"  Length : {chunk['length']}\n")
            self.parse_text.insert(tk.END, f"  Value  : {format_hex(chunk['value'][:20])}{'...' if len(chunk['value']) > 20 else ''}\n\n")

# ============================================================
# ONGLET : MULTI-HOMING & MULTI-STREAMING
# ============================================================

class MultiFeatureTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Multi-homing & Multi-streaming",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        controls = tk.Frame(self, bg=CARD_BG)
        controls.pack(fill=tk.X, padx=20, pady=5)

        self.var_stream_count = tk.IntVar(value=3)
        tk.Label(controls, text="Nombre de streams:", fg=TEXT_COLOR, bg=CARD_BG, font=(FONT_FAMILY, 10)).pack(side=tk.LEFT, padx=5)
        tk.Spinbox(controls, from_=1, to=8, textvariable=self.var_stream_count, width=5, font=(FONT_FAMILY, 10)).pack(side=tk.LEFT, padx=5)

        self.var_failover = tk.BooleanVar(value=False)
        tk.Checkbutton(
            controls,
            text="Simuler panne chemin principal",
            variable=self.var_failover,
            fg=TEXT_COLOR,
            bg=CARD_BG,
            selectcolor=BG_COLOR,
            activebackground=CARD_BG,
            activeforeground=TEXT_COLOR,
            font=(FONT_FAMILY, 10),
        ).pack(side=tk.LEFT, padx=20)

        tk.Button(
            controls,
            text="Lancer la simulation",
            command=self.simulate,
            bg=SUCCESS,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        ).pack(side=tk.RIGHT, padx=5)

        self.canvas = tk.Canvas(self, bg=BG_COLOR, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.log = scrolledtext.ScrolledText(
            self,
            height=8,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.log.pack(fill=tk.X, padx=20, pady=10)
        self.log.insert(tk.END, "Configurez les paramètres et lancez la simulation.\n")

    def simulate(self):
        self.canvas.delete("all")
        self.log.delete("1.0", tk.END)
        streams = self.var_stream_count.get()
        failover = self.var_failover.get()

        cw = self.canvas.winfo_width() or 900
        ch = self.canvas.winfo_height() or 400

        # Hosts
        self.canvas.create_rectangle(50, ch // 2 - 40, 150, ch // 2 + 40, fill="#334155", outline=ACCENT, width=2)
        self.canvas.create_text(100, ch // 2, text="Client\n[IP-A, IP-B]", fill="white", font=(FONT_FAMILY, 10, "bold"))

        self.canvas.create_rectangle(cw - 150, ch // 2 - 40, cw - 50, ch // 2 + 40, fill="#334155", outline=ACCENT, width=2)
        self.canvas.create_text(cw - 100, ch // 2, text="Serveur\n[IP-X, IP-Y]", fill="white", font=(FONT_FAMILY, 10, "bold"))

        # Paths
        primary_color = SUCCESS if not failover else DANGER
        self.canvas.create_line(150, ch // 2 - 20, cw - 150, ch // 2 - 20, fill=primary_color, width=3, dash=(10, 5))
        self.canvas.create_text(cw // 2, ch // 2 - 35, text="Chemin principal", fill=primary_color, font=(FONT_FAMILY, 9))

        self.canvas.create_line(150, ch // 2 + 20, cw - 150, ch // 2 + 20, fill=WARNING, width=2)
        self.canvas.create_text(cw // 2, ch // 2 + 35, text="Chemin secondaire (backup)", fill=WARNING, font=(FONT_FAMILY, 9))

        self.log.insert(tk.END, f"Association SCTP avec {streams} streams actives.\n")
        if failover:
            self.log.insert(tk.END, "Panne détectée sur le chemin principal ! Basculement vers IP-B -> IP-Y.\n")
        else:
            self.log.insert(tk.END, "Trafic transite par le chemin principal IP-A -> IP-X.\n")

        colors = ["#f87171", "#fbbf24", "#34d399", "#60a5fa", "#a78bfa", "#f472b6", "#22d3ee", "#a3e635"]
        for s in range(streams):
            y_offset = -60 + s * 25
            path_y = ch // 2 + (20 if failover else -20)
            color = colors[s % len(colors)]
            self.canvas.create_line(150, ch // 2 + y_offset, cw - 150, path_y, fill=color, width=2, arrow=tk.LAST)
            self.canvas.create_text(cw // 2, (ch // 2 + y_offset + path_y) // 2 - 10, text=f"Stream {s}", fill=color, font=(FONT_FAMILY, 9))
            self.log.insert(tk.END, f"Stream {s}: données envoyées indépendamment des autres streams.\n")

        self.log.insert(tk.END, "Avantage : un paquet perdu sur un stream ne bloque pas les autres streams.\n")

# ============================================================
# ONGLET : ANALYSEUR DE PAQUETS
# ============================================================

class PacketAnalyzerTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.sim = SCTPPacketSimulator()
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Analyseur de paquets SCTP",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        btn_frame = tk.Frame(header, bg=CARD_BG)
        btn_frame.pack(side=tk.RIGHT, padx=20)

        tk.Button(
            btn_frame,
            text="Charger un fichier binaire",
            command=self.load_file,
            bg=ACCENT,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame,
            text="Paquet exemple",
            command=self.load_example,
            bg=SUCCESS,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=5,
        ).pack(side=tk.LEFT, padx=5)

        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=CARD_BG)
        paned.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        left = tk.Frame(paned, bg=BG_COLOR)
        paned.add(left, width=450)
        tk.Label(left, text="Hex dump brut", fg=ACCENT, bg=BG_COLOR, font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=10, pady=5)
        self.hex_input = scrolledtext.ScrolledText(
            left,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.hex_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        right = tk.Frame(paned, bg=BG_COLOR)
        paned.add(right, width=450)
        tk.Label(right, text="Résultat de l'analyse", fg=ACCENT, bg=BG_COLOR, font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=10, pady=5)
        self.analysis_output = scrolledtext.ScrolledText(
            right,
            bg=BG_COLOR,
            fg=SUCCESS,
            font=(FONT_MONO, 10),
            insertbackground=ACCENT,
        )
        self.analysis_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tk.Button(
            self,
            text="Analyser",
            command=self.analyze,
            bg=WARNING,
            fg=BG_COLOR,
            font=(FONT_FAMILY, 11, "bold"),
            relief=tk.FLAT,
            padx=20,
            pady=5,
        ).pack(pady=10)

    def load_example(self):
        init_chunk = self.sim.build_init_chunk(init_tag=0xAABBCCDD)
        packet = self.sim.build_packet([init_chunk])
        self.hex_input.delete("1.0", tk.END)
        self.hex_input.insert(tk.END, format_hex(packet))
        self.analyze()

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Fichiers binaires", "*.bin *.pcap *.raw"), ("Tous", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.hex_input.delete("1.0", tk.END)
            self.hex_input.insert(tk.END, format_hex(data))
            self.analyze()
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def analyze(self):
        raw = self.hex_input.get("1.0", tk.END).strip()
        try:
            data = bytes.fromhex(raw.replace(" ", "").replace("\n", ""))
        except ValueError:
            self.analysis_output.delete("1.0", tk.END)
            self.analysis_output.insert(tk.END, "Erreur : hex dump invalide.\n")
            return

        parsed = self.sim.parse_packet(data)
        self.analysis_output.delete("1.0", tk.END)
        if "error" in parsed:
            self.analysis_output.insert(tk.END, f"Erreur: {parsed['error']}\n")
            return

        self.analysis_output.insert(tk.END, "=== SCTP Packet Analysis ===\n")
        self.analysis_output.insert(tk.END, f"Source Port      : {parsed['src_port']}\n")
        self.analysis_output.insert(tk.END, f"Destination Port : {parsed['dst_port']}\n")
        self.analysis_output.insert(tk.END, f"Verification Tag : {parsed['verification_tag']}\n")
        self.analysis_output.insert(tk.END, f"Checksum (Adler) : {parsed['checksum']}\n\n")
        self.analysis_output.insert(tk.END, f"Chunks ({len(parsed['chunks'])}):\n")
        for idx, chunk in enumerate(parsed["chunks"], 1):
            self.analysis_output.insert(tk.END, f"  [{idx}] {chunk['name']} (type={chunk['type']}, flags=0x{chunk['flags']:02x}, len={chunk['length']})\n")
            if chunk["name"] == "INIT":
                if len(chunk["value"]) >= 16:
                    it, rwnd, os, is_, tsn = struct.unpack("!IIHHI", chunk["value"][:16])
                    self.analysis_output.insert(tk.END, f"        Initiate Tag : 0x{it:08x}\n")
                    self.analysis_output.insert(tk.END, f"        Advertised Rwnd : {rwnd}\n")
                    self.analysis_output.insert(tk.END, f"        Outbound Streams : {os}\n")
                    self.analysis_output.insert(tk.END, f"        Inbound Streams  : {is_}\n")
                    self.analysis_output.insert(tk.END, f"        Initial TSN      : {tsn}\n")
            elif chunk["name"] == "DATA":
                if len(chunk["value"]) >= 12:
                    tsn, sid, ssn, ppid = struct.unpack("!IHH I", chunk["value"][:12])
                    payload = chunk["value"][12:]
                    self.analysis_output.insert(tk.END, f"        TSN  : {tsn}\n")
                    self.analysis_output.insert(tk.END, f"        Stream ID : {sid}\n")
                    self.analysis_output.insert(tk.END, f"        Stream SSN: {ssn}\n")
                    self.analysis_output.insert(tk.END, f"        Payload Protocol Identifier : {ppid}\n")
                    self.analysis_output.insert(tk.END, f"        Payload : {payload!r}\n")

# ============================================================
# ONGLET : COMMANDES LINUX
# ============================================================

class CommandsTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Commandes Linux & Réseau pour SCTP",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        content = tk.Frame(self, bg=CARD_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        for title, cmd in COMMANDS:
            card = tk.Frame(content, bg=BG_COLOR, bd=1, relief=tk.RIDGE)
            card.pack(fill=tk.X, pady=5)
            tk.Label(card, text=title, fg=ACCENT, bg=BG_COLOR, font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
            txt = tk.Text(card, height=2, bg="#0f172a", fg=SUCCESS, font=(FONT_MONO, 10), insertbackground=ACCENT)
            txt.pack(fill=tk.X, padx=15, pady=(0, 10))
            txt.insert(tk.END, cmd)
            txt.config(state=tk.DISABLED)

        note = tk.Label(
            content,
            text="Note : certaines commandes nécessitent les privilèges root ou la prise en charge SCTP du noyau.",
            fg=WARNING,
            bg=CARD_BG,
            font=(FONT_FAMILY, 10),
        )
        note.pack(pady=10)

# ============================================================
# ONGLET : DOCUMENTATION / README INTÉGRÉ
# ============================================================

class DocumentationTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        header = tk.Frame(self, bg=CARD_BG)
        header.pack(fill=tk.X, pady=10)
        tk.Label(
            header,
            text="Documentation & Ressources SCTP",
            font=(FONT_FAMILY, 18, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20)

        self.doc_text = scrolledtext.ScrolledText(
            self,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            font=(FONT_FAMILY, 11),
            insertbackground=ACCENT,
        )
        self.doc_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        self.doc_text.insert(tk.END, self.build_readme())

        resources_frame = tk.LabelFrame(self, text="Ressources officielles", fg=ACCENT, bg=CARD_BG, font=(FONT_FAMILY, 12, "bold"))
        resources_frame.pack(fill=tk.X, padx=20, pady=10)
        for title, url in RESOURCES:
            lbl = tk.Label(
                resources_frame,
                text=f"{title}: {url}",
                fg="#60a5fa",
                bg=CARD_BG,
                font=(FONT_FAMILY, 10),
                cursor="hand2",
            )
            lbl.pack(anchor="w", padx=10, pady=2)
            lbl.bind("<Button-1>", lambda e, u=url: self.open_url(u))

    def build_readme(self) -> str:
        return """
# SCTP_TECHNOLOGY

Application éducative avancée en Python/Tkinter pour explorer le protocole SCTP
(Stream Control Transmission Protocol, RFC 4960).

## Table des matières
1. Présentation
2. Fonctionnalités
3. Installation
4. Utilisation
5. Architecture du code
6. Commandes utiles
7. Ressources
8. Licence

## 1. Présentation

SCTP est un protocole de transport fiable, orienté connexion, message-oriented.
Il est utilisé dans la signalisation téléphonique (SIGTRAN, Diameter, WebRTC DataChannel)
et résout plusieurs limitations de TCP grâce au multi-streaming et au multi-homing.

## 2. Fonctionnalités

- Vue d'ensemble des concepts SCTP
- Simulation 3D du handshake SCTP (4-way)
- Structure d'un paquet SCTP avec génération hexadécimale
- Simulation multi-homing / multi-streaming
- Analyseur de paquets SCTP binaires
- Commandes Linux et réseau
- Documentation intégrée avec liens vers les RFC

## 3. Installation

```bash
# Cloner ou copier les fichiers
cd /workspace

# Créer un environnement virtuel (optionnel mais recommandé)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r requirements.txt
```

## 4. Utilisation

```bash
python3 sctp_technology.py
```

L'interface s'ouvre avec plusieurs onglets :
- Overview : concepts clés
- Handshake 3D : visualisation du 4-way handshake
- Packet Structure : structure d'un paquet SCTP
- Multi-homing/Streaming : simulation de failover et streams
- Packet Analyzer : analyse de paquets binaires
- Commands : commandes Linux pour SCTP
- Documentation : README intégré

## 5. Architecture du code

- `sctp_technology.py` : application principale (1000+ lignes)
- Classes d'onglets héritant de `ttk.Frame`
- `SCTPPacketSimulator` : génération/parsing de paquets SCTP
- `Pseudo3DCanvas` : rendu 3D simplifié sur Canvas Tkinter

## 6. Commandes utiles

```bash
# Vérifier le support SCTP du noyau
lsmod | grep sctp

# Lister les sockets SCTP
ss -tan | grep sctp

# Capturer du trafic SCTP
sudo tcpdump -i any sctp -w capture.pcap

# Ouvrir avec Wireshark
wireshark capture.pcap
```

## 7. Ressources

- RFC 4960 : https://tools.ietf.org/html/rfc4960
- RFC 3286 : https://tools.ietf.org/html/rfc3286
- RFC 5061 : https://tools.ietf.org/html/rfc5061
- RFC 6525 : https://tools.ietf.org/html/rfc6525
- Wikipedia : https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol
- Wireshark SCTP : https://wiki.wireshark.org/SCTP

## 8. Licence

MIT License - CodePal
"""

    def open_url(self, url: str):
        import webbrowser
        webbrowser.open_new(url)

# ============================================================
# APPLICATION PRINCIPALE
# ============================================================

class SCTPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SCTP_TECHNOLOGY")
        self.geometry("1200x800")
        self.configure(bg=BG_COLOR)
        self.setup_styles()
        self.create_menu()
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_COLOR, tabmargins=[2, 5, 2, 0])
        style.configure(
            "TNotebook.Tab",
            background=CARD_BG,
            foreground=TEXT_COLOR,
            font=(FONT_FAMILY, 10, "bold"),
            padding=[15, 8],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT)],
            foreground=[("selected", BG_COLOR)],
        )
        style.configure("Card.TFrame", background=CARD_BG)

    def create_menu(self):
        menubar = tk.Menu(self, bg=CARD_BG, fg=TEXT_COLOR, activebackground=ACCENT, activeforeground=BG_COLOR)
        file_menu = tk.Menu(menubar, tearoff=0, bg=CARD_BG, fg=TEXT_COLOR)
        file_menu.add_command(label="Quitter", command=self.destroy)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=CARD_BG, fg=TEXT_COLOR)
        help_menu.add_command(label="À propos", command=self.show_about)
        menubar.add_cascade(label="Aide", menu=help_menu)
        self.config(menu=menubar)

    def create_widgets(self):
        container = tk.Frame(self, bg=BG_COLOR)
        container.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(container, bg=CARD_BG, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(
            header,
            text="SCTP_TECHNOLOGY",
            font=(FONT_FAMILY, 20, "bold"),
            fg=ACCENT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=20, pady=10)
        tk.Label(
            header,
            text="Stream Control Transmission Protocol — RFC 4960",
            font=(FONT_FAMILY, 11),
            fg=SECONDARY_TEXT,
            bg=CARD_BG,
        ).pack(side=tk.LEFT, padx=10, pady=10)

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tabs = {
            "Vue d'ensemble": OverviewTab(self.notebook, self),
            "Handshake 3D": HandshakeTab(self.notebook, self),
            "Structure Paquet": PacketStructureTab(self.notebook, self),
            "Multi-homing/Streaming": MultiFeatureTab(self.notebook, self),
            "Analyseur": PacketAnalyzerTab(self.notebook, self),
            "Commandes": CommandsTab(self.notebook, self),
            "Documentation": DocumentationTab(self.notebook, self),
        }

        for name, tab in self.tabs.items():
            self.notebook.add(tab, text=name)

        footer = tk.Label(
            container,
            text="SCTP_TECHNOLOGY | CodePal | MIT License",
            font=(FONT_FAMILY, 9),
            fg=SECONDARY_TEXT,
            bg=BG_COLOR,
        )
        footer.pack(side=tk.BOTTOM, pady=5)

    def show_about(self):
        messagebox.showinfo(
            "À propos",
            "SCTP_TECHNOLOGY\nApplication éducative avancée sur le protocole SCTP (RFC 4960).\n\nAuteur : CodePal\nLicence : MIT",
        )

    def on_close(self):
        for tab in self.tabs.values():
            if hasattr(tab, "canvas") and isinstance(tab.canvas, Pseudo3DCanvas):
                tab.canvas.stop()
        self.destroy()

# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":
    app = SCTPApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
