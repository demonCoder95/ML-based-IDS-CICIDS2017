'''
 This code implements the flow meter to determine flow statistics for the IDS to extract features

 Author: Noor Muhammad Malik
 Date: April 15, 2018
 License: None

 MULTI-THREADED CODE FOR GUI AND DNN HANDLING

'''
# the structures for flow detection
import networking
# the functions for raw socket data processing
import sniffer
# other standard imports
import socket
import os
import time

# True, True -> exists, and fwd flow
# True, False -> exists, and bwd flow
# False, False -> doesn't exist
def flow_exists(flow, buffer):
    # search for flow in the buffer, using the same id and the reversed id
    if flow.get_flow_id() in buffer:
        return True, True
    elif networking.Flow.make_reverse_flow(flow) in buffer:
        return True, False
    else:
        return False, False

def main():
    # clear screen to begin
    os.system("clear")

    # create sniffer socket and set it to recieve packets
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    # dict() objects to store header information
    ip_header = dict()
    tcp_header = dict()
    udp_header = dict()

    # buffer to store flows for faster in-memory processing
    flow_buffer = dict()

    # print the title head
    print("{0:<46s}{1:<12s} {2:<12s} {3:<12s} {4:<12s} {5:<12s}".format(
        "Flow ID",
        "Packet Count",
        "Time stamp",
        "Fwd Count",
        "Bwd Count",
        "Flow Count"))

    # create a flow object to store the flow data of the first packet
    # current_flow is just a placeholder, which will be updated on each iteration to point to a different
    # Flow() object which will then be stored in the buffer
    current_flow = networking.Flow()

    # start the timer to determine the start of capture, for timestamp feature of software
    start_time = time.time()

    # count number of unique flows currently in the buffer
    flow_count = 0  

    # keep a track of bwd-id and fwd-id to save function calls for faster processing
    bwd_id = ""
    fwd_id = ""

    # run the main program!
    while True:

        flow_count = len(flow_buffer)

        # since max PDU size for ethernet is 1522 bytes, 2048 is a safe value to read from socket
        recv_data = sniffer_socket.recv(2048)
        
        # process the ethernet header and extract ethernet payload
        eth_payload, is_ip = sniffer.check_eth_data(recv_data)

        if is_ip:
            # process the ip header and extract the payload
            ip_payload, ip_header = sniffer.check_ip_data(eth_payload, ip_header)
            # update the flow object attributes
            current_flow.src_ip = ip_header['src_ip']
            current_flow.dest_ip = ip_header['dest_ip']
            current_flow.protocol =  ip_header['protocol']

        # ignore localhost traffic, it's unimportant for an IDS
        if is_ip and ip_header['src_ip'] == "127.0.0.1" or ip_header['dest_ip'] == "127.0.0.1":
            continue
            
        # process the TCP header and extract the TCP payload
        if is_ip and ip_header["protocol"] == 0x6:
            tcp_payload, tcp_header = sniffer.check_tcp_data(ip_payload, tcp_header)
            # update the flow object attributes
            current_flow.src_port = tcp_header['src_port']
            current_flow.dest_port = tcp_header['dest_port']

        # process the UDP header and extract the UDP payload
        elif is_ip and ip_header["protocol"] == 0x11:
            udp_payload, udp_header = sniffer.check_udp_data(ip_payload, udp_header)
            # update the flow object attributes
            current_flow.src_port = udp_header['src_port']
            current_flow.dest_port = udp_header['dest_port']
        else:
            # not really concerned with any other type of data, so just continue to next iteration
            # and save processing time!
            continue


        exist_tuple = flow_exists(current_flow, flow_buffer)

        fwd_id = current_flow.get_flow_id()

        # if a flow doesn't exist, create it, and store it
        if not exist_tuple[0]:
            # determine the time_stamp to determine flow duration
            current_flow.start_time = time.time()

            # print("New Flow Detected: {}".format(current_flow.get_flow_id()))
            # add the flow object to the dict() buffer
            flow_buffer[fwd_id] = current_flow
            
            # increase the packet count
            current_flow.packet_count += 1
            # first packet of flow will always be in the fwd direction
            current_flow.fwd_packet_count += 1

            print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                fwd_id,
                current_flow.packet_count,
                time.time() - start_time, 
                flow_buffer[fwd_id].fwd_packet_count,
                flow_buffer[fwd_id].bwd_packet_count,
                flow_count ))
            # if a flow doesn't exist, create a new flow object to handle the next packet
            current_flow = networking.Flow()

        else:
            # flow already exists in the buffer
            # if it's a fwd packet                
            if exist_tuple[1] and exist_tuple[0]:                
                # if the flow-id is fwd-id, increment fwd_packet_count
                flow_buffer[fwd_id].fwd_packet_count += 1
                flow_buffer[fwd_id].packet_count += 1
                print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                fwd_id,
                flow_buffer[fwd_id].packet_count,
                time.time() - start_time,
                flow_buffer[fwd_id].fwd_packet_count,
                flow_buffer[fwd_id].bwd_packet_count,
                flow_count ))
            # use else for faster processing
            else:
                # only compute the bwd-id in case of bwd packet for faster processing
                bwd_id =  networking.Flow.make_reverse_flow(current_flow)

                # teardown is checked only in case of bwd_packet, since bwd_packet is the final FIN packet
                # of a tcp 4-way teardown!
                # or, a flow might end because of an rst-flag
                # look for tcp first, since udp packets will give key-error for fin_flag!
                if ip_header['protocol'] == 0x6 and (tcp_header['fin_flag'] or tcp_header['rst_flag']) == 1:
                    flow_buffer[bwd_id].duration = int((time.time() - flow_buffer[bwd_id].start_time) * 1000000)
                    print("Flow {0} ended with duration {1:d}!".format(bwd_id, flow_buffer[bwd_id].duration))

                flow_buffer[bwd_id].bwd_packet_count += 1
                flow_buffer[bwd_id].packet_count += 1
                print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                bwd_id,
                flow_buffer[bwd_id].packet_count,
                time.time() - start_time,
                flow_buffer[bwd_id].fwd_packet_count,
                flow_buffer[bwd_id].bwd_packet_count,
                flow_count ))

if __name__=="__main__":
    main()