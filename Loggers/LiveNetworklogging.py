from abc import update_abstractmethods
from turtle import update
import scapy
from scapy.all import sniff, IP, TCP
from scapy.arch.windows import get_windows_if_list
from datetime import datetime
import socket

class livenetworklogger:
    def __init__(self, interface= None):
        self.interface = None


    
    def start_sniffing(self, update_callback):
        sniff(
            iface=self.interface,
            prn=lambda packet: self.process_packet(packet, update_callback),
            store=False,
            filter="ip",  # Alleen IP-verkeer loggen (je kunt dit aanpassen)
        )

    def process_packet(self, packet, update_callback):
        if not packet.haslayer(IP):
            return

        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = packet.sprintf("%IP.proto%")

        src_port = dst_port = "-"
        flags = "-"
        action_str = "UNKNOWN"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags

            if flags == "S":
                action_str = "SYN_SENT"
            elif flags == "SA":
                action_str = "SYN_ACK"
            elif flags == "RA" or flags == "R":
                action_str = "REFUSED"
            elif flags == "A":
                action_str = "ACCEPTED"
            else:
                action_str = str(flags)

        packet_dict = {
            "date": date_str,
            "time": time_str,
            "action": action_str,
            "protocol": protocol,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "size": len(packet),
            "flags": str(flags),
        }

        update_callback(packet_dict)



