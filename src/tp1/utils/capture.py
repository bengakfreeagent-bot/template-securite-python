import os
from collections import Counter

from scapy.all import TCP, Raw, rdpcap, sniff

from tp1.utils.config import logger
from tp1.utils.lib import choose_interface

IGNORED_LAYERS = {"Raw", "Padding"}
LAYER_NAMES = {"Ether": "Ethernet"}
HTTP_PORTS = {80}


class Capture:
    def __init__(self, pcap_file: str | None = None, iface: str | None = None) -> None:
        self.pcap_file = pcap_file
        self.interface = iface or ""
        self.summary = ""
        self.packets = []
        self.protocols = Counter()

    def capture_traffic(self) -> None:
        """
        Read the pcap file if given, otherwise capture from the interface
        """
        if self.pcap_file:
            if not os.path.exists(self.pcap_file):
                raise FileNotFoundError(f"Fichier pcap introuvable : {self.pcap_file}")
            logger.info(f"Reading packets from {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
        else:
            if not self.interface:
                self.interface = choose_interface()
            logger.info(f"Capture traffic from interface {self.interface}")
            self.packets = sniff(iface=self.interface or None, timeout=30)
        logger.info(f"{len(self.packets)} packets loaded")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Count packets per protocol and return them as text
        """
        self.protocols = Counter()
        for packet in self.packets:
            seen = set()
            for layer in packet.layers():
                name = layer.__name__
                if name in IGNORED_LAYERS:
                    continue
                seen.add(LAYER_NAMES.get(name, name))

            if packet.haslayer(TCP) and packet.haslayer(Raw):
                tcp = packet[TCP]
                if tcp.sport in HTTP_PORTS or tcp.dport in HTTP_PORTS:
                    seen.add("HTTP")

            for name in seen:
                self.protocols[name] += 1

        result = ", ".join(f"{name}: {count}" for name, count in self.protocols.most_common())
        logger.info(f"Protocols: {result}")
        return result

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP
        Spoofing, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon afficher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary