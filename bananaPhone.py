# Created by Frederic Rohrer for Python 3
# Partial code from https://www.binarytides.com/raw-socket-programming-in-python-linux/
import socket, sys, random
import argparse, os
from cryptography.fernet import Fernet
from struct import *

argParser = argparse.ArgumentParser(description='Send custom TCP packets.')
argParser.add_argument('dest', nargs=1, help='The destination IPv4 address')
argParser.add_argument('-i', dest='i', nargs=1, help='Location of file with data to send.')
argParser.add_argument('-r', dest='r', action='store_true', help='Randomize outgoing and incoming port for each packet to avoid detection.')
argParser.add_argument('-e', dest='e', action='store_true', help='Encrypt packet body using SHA256.')

args = argParser.parse_args()

# key = Fernet.generate_key()
key = b'M7Mu5Mg62Hc36oPbhMfx5GW7mb5BejU7a2SYdHlb3Uo='
cipher_suite = Fernet(key)

def encrypt(string):
    return cipher_suite.encrypt(string)
    # decoded_text = cipher_suite.decrypt(encoded_text)

def tcp_checksum(full_tcp):
    values = full_tcp
    #values = map(ord,full_tcp)
    #values = list(values)
    #print(values)

    return len(values)

    # if ((len(values)>>1)<<1) != len(values):
    #     values.append(0) # odd length
    #     s = sum([values[i]+(values[i+1]< 0xffff)])
    #     s = (s>>16) + (s & 0xffff)
    #     return s ^ 0xffff;

class packet:
    def __init__(tcp):

        if args.dest[0]:
            tcp.dest_ip = args.dest[0]
        else:
            tcp.dest_ip = input('Provide Destination IP address (Enter for default 192.168.1.2)') or '192.168.1.2';

        tcp.source_ip = input('Provide Source IP address (Enter for default 192.168.1.99)') or '192.168.1.99';

        if args.r:
            print('Using random source and destination port numbers (above 1024)')
        else:
            tcp.source = int(input('Source Port (Enter for 1234)') or '1234'); # Source port
            tcp.dest = int(input('Destination Port (Enter for 80)') or 80); # Destination port

        tcp.seq = int(input('TCP Sequence Number (Enter for 0)') or 0); # TCP sequence number
        tcp.ack_seq = 0 # Acknlowdege sequence number
        tcp.doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp.fin = int(input('FIN flag (Enter to set to 0)') or 0);
        tcp.syn = int(input('SYN flag (Enter to set to 1)') or 1);
        tcp.rst = int(input('RST flag (Enter to set to 0)') or 0);
        tcp.psh = 0 #PSH is for escalating a packet to layer 4 immediately (no further data should be collected by layer 3)
        tcp.ack = int(input('ACK flag (Enter to set to 0)') or 0);
        tcp.urg = int(input('URG flag (Enter to set to 0)') or 0);
        tcp.window = socket.htons(5840)	# maximum allowed window size
        tcp.check = 0
        tcp.urg_ptr = 0

        if args.i:
            print('Not asking for number of packets to send since a file will be sent.')
            tcp.limit = 1
        else:
            tcp.limit = int(input('How often should this packet be sent? (Enter for once)') or 1);
        tcp.real = input('Should this packet use incremental sequence numbers? (y/N)') or 'n';

def loadInput(args):
    return packet();

def main(args):
    packet = ''; # Initialize packet as string, later we will use pack() to add packet header bits to it
    bodyfromFile = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        print('\n\n\n\n*** BananaPhone Version 1.2 *** \n\n (C) Frederic Rohrer \n\n Did you confuse your Wireshark today? \n\n Use at own discretion! No warranty or help if you break anything.\n\n');
        print('BananaPhone Version 1.2 initialized. \n Socket was created. Now filling in TCP Header information.')
        print('--- Encryption Key initialized ---\n',key.decode('utf-8'),'\n')
    except socket.error:
    	print('BananaPhone failed to initialize: Socket could not be created. Make sure you are running as root/sudo.')
    	sys.exit()

    if args.i:
        print('Reading',args.i[0])
        filepath = args.i[0]
        if not os.path.isfile(filepath):
            print('Having trouble reading this file.')
        else:
            with open(filepath) as fp:
               bodyfromFile = fp.readlines()

    tcp = loadInput(args) #load the user input data

    # ip header fields
    ip_ihl = 5 # Internet Header Length
    ip_ver = 4 # Protocol Version (IPv4 or IPv6)
    ip_tos = 0 # Type of service (the higher the less important priority)
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = 0;	# Id of this packet
    ip_frag_off = 0 # Fragmentation off/on
    ip_ttl = 255 # Time to Live, each "hop" will subtract one
    ip_proto = socket.IPPROTO_TCP # Protocol (TCP)
    ip_check = 0	# kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( tcp.source_ip ) # Source IP (can be spoofed)
    ip_daddr = socket.inet_aton ( tcp.dest_ip ) # Destination IP

    loop = 0;

    if len(bodyfromFile) == 0:
        tcp.limit = 1
    else:
        tcp.limit = len(bodyfromFile)

    while loop < tcp.limit:

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        tcp_offset_res = (tcp.doff << 4) + 0
        tcp_flags = tcp.fin + (tcp.syn << 1) + (tcp.rst << 2) + (tcp.psh << 3) + (tcp.ack << 4) + (tcp.urg << 5)

        if args.r:
            tcp.source = random.randint(1024,54000)
            tcp.dest = random.randint(1024,54000)
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , tcp.source, tcp.dest, tcp.seq, tcp.ack_seq, tcp_offset_res, tcp_flags,  tcp.window, tcp.check, tcp.urg_ptr)

        if len(bodyfromFile) > 0:
            user_data = str.encode(bodyfromFile[loop])
        else:
            user_data = b'BananaPhone calls you!'

        if args.e:
            user_data = encrypt(user_data)

        #Insert header fields
        source_address = socket.inet_aton(tcp.source_ip)
        dest_address = socket.inet_aton(tcp.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        #
        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        tcp_check = tcp_checksum(psh)

        #Create the header again with full checksum
        tcp_header = pack('!HHLLBBH' , tcp.source, tcp.dest, tcp.seq, tcp.ack_seq, tcp_offset_res, tcp_flags,  tcp.window) + pack('H' , tcp_check) + pack('!H' , tcp.urg_ptr)

        packet = ip_header + tcp_header + user_data

        s.sendto(packet,(tcp.dest_ip , 0))

        loop += 1;
        if tcp.real == 'yes' or 'y' or 'yeah':
            ip_id += 1;
            tcp.seq += 1;
            if loop % 100 == 0:
                print('...')

    print('Done.',loop,'packets were sent.')
main(args)
