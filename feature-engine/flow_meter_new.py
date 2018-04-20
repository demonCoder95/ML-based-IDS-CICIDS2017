import socket
import sniffer
import binascii
import time
import networking

def main():
    # raw socket for sniffing
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    # create a new Flow object to identify flows in packets
    packet_flow = networking.Flow()

    # dict object to hold the ip header information
    ip_header = dict()
    # dict object to hold the tcp header information
    tcp_header = dict()
    # dict object to hold the udp header information
    udp_header = dict()

    while(True):
        # capture data from socket
        captured_data = sniffer_socket.recv(2048)

        # process and discard the ethernet header, and extract IP payload
        eth_payload, is_ip = sniffer.check_eth_data(captured_data)

        if is_ip:
            ip_payload, ip_header = sniffer.check_ip_data(eth_payload, ip_header)
            packet_flow.set_ip_vars(ip_header['src_ip'], ip_header['dest_ip'], ip_header['protocol'])

        # process the TCP header and extract the TCP payload
        if is_ip and (ip_header['protocol'] == 0x6):
            tcp_payload, tcp_header = sniffer.check_tcp_data(ip_payload, tcp_header)
            packet_flow.src_port = tcp_header['src_port']
            packet_flow.dest_port = tcp_header['dest_port']
            #print("TCP Payload:\nHex - {1}\nASCII - {0}".format(tcp_payload, binascii.hexlify(tcp_payload)))
        elif is_ip and (ip_header['protocol'] == 0x11):
            udp_payload, udp_header = sniffer.check_udp_data(ip_payload, udp_header)
            packet_flow.src_port = udp_header['src_port']
            packet_flow.dest_port = udp_header['dest_port']
        #    print("UDP Payload:\nHex - {1}\nASCII - {0}".format(udp_payload, binascii.hexlify(udp_payload)))

        if is_ip:
            print("Packet Detected with Flow-ID: {}".format(packet_flow.get_flow_id()))

        
        

main()
    