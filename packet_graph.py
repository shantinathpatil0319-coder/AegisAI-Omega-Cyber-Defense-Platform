from scapy.all import sniff
import time

traffic = []

def process(pkt):
    traffic.append({
        "time": time.time(),
        "size": len(pkt)
    })

def start_sniff():
    sniff(prn=process, count=15)

def get_graph():
    return traffic[-15:]