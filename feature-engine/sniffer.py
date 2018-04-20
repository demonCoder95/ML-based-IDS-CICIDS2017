# This script implements the LINUX version of the packet sniffer
import socket
import os
import struct
import binascii

# this function processes the ethernet header
def check_eth_data(data):
    # extract the ethernet header from the packet - 14 bytes long
    # it is in the form of a binary 'stucture' 
    # ! is the 'network-endianness'
    # 6s - 6-bytes char - of dest MAC
    # 6s - 6-bytes char - of src MAC
    # H  - 2-bytes unsigned short - ipv4 - 0x0800 in 2-byte protocol number field, next layer protocol
    eth_hdr = struct.unpack('!6s6sH', data[:14])

    # convert binary data to hex representation
    # dest_mac = binascii.hexlify(eth_hdr[0])
    # src_mac  = binascii.hexlify(eth_hdr[1])
    protocol = eth_hdr[2]

    # print the eth layer data
    # print("Ethernet Header Data:")
    # print("Dest MAC: {0}\tSrc MAC: {1}\tProtocol: 0x{2:04x}".format(dest_mac, src_mac, protocol))

    is_ip = False
    if protocol == 0x0800:
        is_ip = True

    # slice off the eth_header
    payload = data[14:]
    return payload, is_ip

# this function processes the ip header - rfc791
def check_ip_data(data, ip_header):
    # header length is 20 bytes
    # H - 2 byte chunk of binary data - contains ver, ihl, tos fields
    # H - 2 byte total length field
    # H - 2 byte ip identifier
    ip_hdr = struct.unpack('!HHHHHH4s4s', data[:20])
    # left 4 bits are version, so SHR by 12 bits to extract that
    # ver = ip_hdr[0] >> 12
    # middle 4 bits are internet header length, SHR by 8 and 'and' to get rightmost 4 bits
    # ihl = (ip_hdr[0] >> 8) & 0x0f
    # last 8 bits are TOS, simply and with 0xff
    # tos = ip_hdr[0] & 0xff
    # 2 bytes of packet length
    total_length = ip_hdr[1]
    # 2 bytes of IP identifier
    # id = ip_hdr[2]
    # 3 bits of flags
    # flags = ip_hdr[3] >> 13
    # 13 bits of frag_offset
    # frag_offset = ip_hdr[3] & 0x1fff
    # 8 bits of TTL
    # ttl = ip_hdr[4] >> 8
    # 8 bits of protocol number
    protocol = ip_hdr[4] & 0xff
    # 16 bits of internet checksum
    # checksum = ip_hdr[5]
    # 4 bytes of src and dest ip addresses
    src_ip = socket.inet_ntoa(ip_hdr[6])
    dest_ip = socket.inet_ntoa(ip_hdr[7])

    # print("\nIP Header Data:")
    # print("Version: 0x{0:1x}\tIHL: 0x{1:1x}\t\tTOS: 0x{2:02x}\t\tTotal Length: 0x{3:04x}".format(ver, ihl, tos, total_length))
    # print("Id: 0x{0:04x}\tFlags: {1:03b} R D M\tFrag Offset: 0x{2:04x}\tTTL: 0x{3:02x}".format(id, flags & 0b111, frag_offset, ttl))
    # print("Protocol: 0x{0:02x}\tHeader Checksum: 0x{1:04x}".format(protocol, checksum))
    # print("Source IP: {0}\t\tDest IP: {1}".format(src_ip, dest_ip))

    # modify the given dict() object to return the header information to the caller
    ip_header['src_ip'] = src_ip
    ip_header['dest_ip'] = dest_ip
    ip_header['protocol'] = protocol
    ip_header['total_length'] = total_length

    # strip off the ip header
    data = data[20:]
    return data, ip_header

# this function processes the TCP header - rfc793
def check_tcp_data(data, tcp_header):
    # header length is 20 bytes
    # H - 2 bytes of source port
    # H - 2 bytes of dest port
    # I - 4 bytes of SEQ num
    # I - 4 bytes of ACK num
    # H - 2 bytes of offset+reserved+flags
    # H - 2 bytes of window size
    # H - 2 bytes of checksum
    # H - 2 bytes of Urg Pointer
    tcp_hdr = struct.unpack('!HHIIHHHH', data[:20])
    src_port = tcp_hdr[0]
    dest_port = tcp_hdr[1]
    # seq_num = tcp_hdr[2]
    # ack_num = tcp_hdr[3]
    # 4 bits of offset
    # data_offset = tcp_hdr[4] >> 12
    # next 6 bits are reserved 
    # reserved = (tcp_hdr[4] >> 6) & 0x3f
    # next 6 bits are flags
    flags = tcp_hdr[4] & 0x3f
    # separate each flag individually
    urg_flag = (flags & 0x20) >> 5
    ack_flag = (flags & 0x10) >> 4
    psh_flag = (flags & 0x08) >> 3
    rst_flag = (flags & 0x04) >> 2
    syn_flag = (flags & 0x02) >> 1
    fin_flag = flags & 0x01
    # window size
    window = tcp_hdr[5]
    # checksum
    # checksum = tcp_hdr[6]
    # urgent pointer
    # urg_ptr = tcp_hdr[7]

    # print("\nTCP Header Data:")
    # print("Source Port: {0}\tDest Port: {1}\tSeq Num: {2}\tAck Num: {3}".format(src_port, dest_port, seq_num, ack_num))
    # print("Data Offset: 0x{0:1x}\tReserved: 0x{1:02x}\t\tFlags: {2:06b}".format(data_offset, reserved, flags & 0b111111))
    # print("URG={0:1b}\tACK={1:1b}\tPSH={2:1b}\tRST={3:1b}\tSYN={4:1b}\tFIN={5:1b}".format(urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag))
    # print("Window: {0}\tChecksum: 0x{1:04x}\tUrgent Pointer: 0x{2:04x}".format(window, checksum, urg_ptr))

    # modify the given dict() object to return tcp header data
    tcp_header['src_port'] = src_port
    tcp_header['dest_port'] = dest_port
    tcp_header['win_size'] = window
    tcp_header['urg_flag'] = urg_flag
    tcp_header['ack_flag'] = ack_flag
    tcp_header['psh_flag'] = psh_flag
    tcp_header['rst_flag'] = rst_flag
    tcp_header['syn_flag'] = syn_flag
    tcp_header['fin_flag'] = fin_flag

    data = data[20:]
#    print("Payload:     {0} Bytes\n{1}".format(len(data), binascii.hexlify(data)))
    return data, tcp_header

# this function processes the UDP header - rfc 768
def check_udp_data(data, udp_header):
    udp_hdr = struct.unpack('!HHHH',data[:8] )
    src_port = udp_hdr[0]
    dest_port = udp_hdr[1]
    # length = udp_hdr[2]
    # checksum = udp_hdr[3]

    # print("\nUDP Header Data:")
    # print("Source Port: {0:>5}\tDest Port: {1:>5}".format(src_port, dest_port))
    # print("Length: {0:>10}\tChecksum: 0x{1:04x}".format(length, checksum))

    udp_header['src_port'] = src_port
    udp_header['dest_port'] = dest_port
    # udp_header['length'] = length

    data = data[8:]
    # print("Payload:     {0} Bytes\n{1}".format(len(data), binascii.hexlify(data)))
    
    return data, udp_header

# def main():
#     os.system("clear")

#     # create sniffer socket and set it to recieve packets
#     sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
#     recv_data = sniffer_socket.recv(2048)

#     # process the ethernet header and extract payload
#     payload, is_ip = check_eth_data(recv_data)

#     # process the ip header and extract the payload
#     if is_ip:
#         payload, next_protocol = check_ip_data(payload)

#     # process the TCP header and extract the TCP payload
#     if next_protocol == "TCP":
#         payload = check_tcp_data(payload)

#     # process the UDP header and extract the UDP payload
#     elif next_protocol == "UDP":
#         payload = check_udp_data(payload)
#     else:
#         return
    
# main()