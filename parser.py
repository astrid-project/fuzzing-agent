import os
import sys
import zlib
import uuid
import re
import subprocess
from scapy.all import *

def add_testcase(fuzz_instance, file):
    file_name = max([int(each) for each in os.listdir(fuzz_instance.testing_dir)])
    if not file_name :
        file_name = 0
    file_name = file_name + 1
    f = open(fuzz_instance.testing_dir + "/" + str(file_name), "wb")
    f.write(file)
    f.close()

def extract_payload(fuzz_instance, http_headers, payload):
    payload_type = http_headers["Content-Type"].split("/")[1].split(";")[0]
    try:
        if "Content-Encoding" in http_headers.keys():
            if http_headers["Content-Encoding"] == "gzip":
                file = zlib.decompress(payload, 16+zlib.MAX_WBITS)
            elif http_headers["Content-Encoding"] == "deflate":
                file = zlib.decompress(payload)
            else:
                file = payload
        else:
            file = payload
    except:
        pass

    filename = uuid.uuid4().hex + "." + payload_type
    add_testcase(fuzz_instance, file)
    return

def striptxt_pcap(fuzz_instance, pcap):
    a = rdpcap(pcap)
    sessions = a.sessions()
    for session in sessions:
        http_payload = b""
        for packet in sessions[session]:
            try:
                if packet[TCP].sport == 80:
                    payload = bytes(packet[TCP].payload)
                    http_header_exists = False
                    try:
                        http_header = payload[payload.index(b"HTTP/1.1"):payload.index(b"\r\n\r\n")+2]
                        if http_header:
                            http_header_exists = True
                    except:
                        pass
                    if http_header_exists:
                        http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
                        http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                        if "Content-Type" in http_header_parsed.keys():
                            if "text" in http_header_parsed["Content-Type"]:
                                txt_payload = payload[payload.index(b"\r\n\r\n")+4:]
                                if txt_payload:
                                    extract_payload(fuzz_instance, http_header_parsed, txt_payload)
            except:
                pass
    return

def http_payloads(fuzz_instance, fixed_path) : 
    pkts = rdpcap(fixed_path)
    for pkt in pkts:
        if TCP in pkt and pkt[TCP].dport == 80 :
            if pkt[TCP].payload :
                add_testcase(fuzz_instance, bytes(pkt[TCP].payload))

def parse_instance(fuzz_instance) :
    file_path = "./pcap/dump.pcap"
    fixed_path = "./pcap/fixed_dump.pcap"

    if not os.path.isfile(file_path):
        print("Base pcap was not found")
        return
    
    pcapfix_script = ["pcapfix", file_path, "-o", fixed_path]
    p = subprocess.Popen(pcapfix_script, stdout=subprocess.PIPE)
    p.wait()
    
    if not os.path.isfile(fixed_path):
        fixed_path = file_path
    
    striptxt_pcap(fuzz_instance, fixed_path)
    http_payloads(fuzz_instance, fixed_path)

    if os.path.isfile(file_path):
        os.remove(file_path)
    
    if os.path.isfile(fixed_path):
        os.remove(fixed_path)
    return 