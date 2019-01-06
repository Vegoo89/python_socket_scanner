import socket
import os
import struct
from ctypes import *

host = socket.gethostbyname(socket.gethostname())


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_ulong),
        ("dst", c_ulong)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        Structure.__init__(self)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as broad_exception:
            print(broad_exception)
            self.protocol = str(self.protocol_num)


# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows we need to send some ioctls
# to setup promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

global_ip_dict = dict()

try:
    while True:
        # read in a single packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])

        if ip_header.src_address not in global_ip_dict:
            try:
                resolved_source = socket.gethostbyaddr(ip_header.src_address)
                real_source = resolved_source[0]
                global_ip_dict[ip_header.src_address] = real_source
            except socket.herror:
                print("Source ip can not be resolved: %s" % ip_header.src_address)
                global_ip_dict[ip_header.src_address] = "Can't be resolved"

        if ip_header.dst_address not in global_ip_dict:
            try:
                resolved_dest = socket.gethostbyaddr(ip_header.dst_address)
                real_destination = resolved_dest[0]
                global_ip_dict[ip_header.dst_address] = real_destination
            except socket.herror:
                print("Destination ip can not be resolved: %s" % ip_header.dst_address)
                global_ip_dict[ip_header.dst_address] = "Can't be resolved"

        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
        print("%s -> %s" % (global_ip_dict[ip_header.src_address], global_ip_dict[ip_header.dst_address]))

except KeyboardInterrupt:
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)