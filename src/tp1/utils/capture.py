import os
from collections import Counter

from scapy.all import rdpcap, sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger

PCAP_FILE = "tp1-grp-4-191ba9.pcap"
IGNORED_LAYERS = {"Ether", "Raw", "Padding"}

class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocols = Counter()

    def capture_traffic(self) -> None:
        """
        Read the pcap file if it exists, otherwise capture from the interface
        """
        if os.path.exists(PCAP_FILE):
            logger.info(f"Reading packets from {PCAP_FILE}")
            self.packets = rdpcap(PCAP_FILE)
        else:
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
            for layer in packet.layers():
                if layer.__name__ not in IGNORED_LAYERS:
                    self.protocols[layer.__name__] += 1
        result = ", ".join(f"{name}: {count}" for name, count in self.protocols.most_common())
        logger.info(f"Protocols: {result}")
        return result

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
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
