'''
 This code implements the flow meter to determine flow statistics for the IDS to extract features

 Author: Noor Muhammad Malik
 Date: April 15, 2018
 License: None

'''
# the structures for flow detection
import networking
# the functions for raw socket data processing
import sniffer
# other standard imports
import socket
import os
import time

class FlowMeter():


    # True, True -> exists, and fwd flow
    # True, False -> exists, and bwd flow
    # False, False -> doesn't exist
    def flow_exists(self, flow, buffer):
        # search for flow in the buffer, using the same id and the reversed id
        if flow.get_flow_id() in buffer:
            return True, True
        elif networking.Flow.make_reverse_flow(flow) in buffer:
            return True, False
        else:
            return False, False

    def __init__(self, q, scan_event, gui_event):
        # clear screen to begin
        os.system("clear")

        # queue for thread synchronization
        self.q = q
        # event object for signalling start and stop of scan
        self.scan_event = scan_event

        # event object for signalling the GUI to refresh itself
        self.gui_event = gui_event

        # create sniffer socket and set it to recieve packets
        self.sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        # dict() objects to store header information
        self.ip_header = dict()
        self.tcp_header = dict()
        self.udp_header = dict()

        # buffer to store flows for faster in-memory processing
        self.flow_buffer = dict()

        # print the title head
        # print("{0:<46s}{1:<12s} {2:<12s} {3:<12s} {4:<12s} {5:<12s}".format(
        #     "Flow ID",
        #     "Packet Count",
        #     "Time stamp",
        #     "Fwd Count",
        #     "Bwd Count",
        #     "Flow Count"))

        # create a flow object to store the flow data of the first packet
        # current_flow is just a placeholder, which will be updated on each iteration to point to a different
        # Flow() object which will then be stored in the buffer
        self.current_flow = networking.Flow()

        # start the timer to determine the start of capture, for timestamp feature of software
        self.start_time = time.time()

        # count number of unique flows currently in the buffer
        self.flow_count = 0  

        # keep a track of bwd-id and fwd-id to save function calls for faster processing
        self.bwd_id = ""
        self.fwd_id = ""

    # run the main flow_meter
    def run_flow_meter(self):
        # wait until the event is signalled by the main thread
        while True:    
            print("[DEBUG] sniffer waiting for event")
            self.scan_event.wait()
            print("[DEBUG] sniffer event happened!")

            # while the scan event is set keep scanning
            # if the event is cleared, the scanning loop ends and the outer loops makes the 
            # thread wait again, for the event to signal again
            while self.scan_event.is_set():

                self.flow_count = len(self.flow_buffer)

                # this is a blocking call, and therefore it might delay
                # scan stop unless a packet is sniffed on the socket
                # the block is released, the stop scan command will take place

                # since max PDU size for ethernet is 1522 bytes, 2048 is a safe value to read from socket
                self.recv_data = self.sniffer_socket.recv(2048)
                
                # process the ethernet header and extract ethernet payload
                self.eth_payload, self.is_ip = sniffer.check_eth_data(self.recv_data)

                if self.is_ip:
                    # process the ip header and extract the payload
                    self.ip_payload, self.ip_header = sniffer.check_ip_data(self.eth_payload, self.ip_header)
                    # update the flow object attributes
                    self.current_flow.src_ip = self.ip_header['src_ip']
                    self.current_flow.dest_ip = self.ip_header['dest_ip']
                    self.current_flow.protocol =  self.ip_header['protocol']

                # ignore localhost traffic, it's unimportant for an IDS
                try:
                    if self.is_ip and self.ip_header['src_ip'] == "127.0.0.1" or self.ip_header['dest_ip'] == "127.0.0.1":
                        continue
                except KeyError:
                    pass
                # process the TCP header and extract the TCP payload
                if self.is_ip and self.ip_header["protocol"] == 0x6:
                    self.tcp_payload, self.tcp_header = sniffer.check_tcp_data(self.ip_payload, self.tcp_header)
                    # update the flow object attributes
                    self.current_flow.src_port = self.tcp_header['src_port']
                    self.current_flow.dest_port = self.tcp_header['dest_port']

                # process the UDP header and extract the UDP payload
                elif self.is_ip and self.ip_header["protocol"] == 0x11:
                    self.udp_payload, self.udp_header = sniffer.check_udp_data(self.ip_payload, self.udp_header)
                    # update the flow object attributes
                    self.current_flow.src_port = self.udp_header['src_port']
                    self.current_flow.dest_port = self.udp_header['dest_port']
                else:
                    # not really concerned with any other type of data, so just continue to next iteration
                    # and save processing time!
                    continue


                self.exist_tuple = self.flow_exists(self.current_flow, self.flow_buffer)

                self.fwd_id = self.current_flow.get_flow_id()

                # if a flow doesn't exist, create it, and store it
                if not self.exist_tuple[0]:
                    # determine the time_stamp to determine flow duration
                    self.current_flow.start_time = time.time()

                    # print("New Flow Detected: {}".format(current_flow.get_flow_id()))
                    # add the flow object to the dict() buffer
                    self.flow_buffer[self.fwd_id] = self.current_flow
                    
                    # increase the packet count
                    self.current_flow.packet_count += 1
                    # first packet of flow will always be in the fwd direction
                    self.current_flow.fwd_packet_count += 1

                    # print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                    #     self.fwd_id,
                    #     self.current_flow.packet_count,
                    #     time.time() - self.start_time, 
                    #     self.flow_buffer[self.fwd_id].fwd_packet_count,
                    #     self.flow_buffer[self.fwd_id].bwd_packet_count,
                    #     self.flow_count ))
                    # if a flow doesn't exist, create a new flow object to handle the next packet
                    self.current_flow = networking.Flow()

                else:
                    # flow already exists in the buffer
                    # if it's a fwd packet                
                    if self.exist_tuple[1] and self.exist_tuple[0]:                
                        # if the flow-id is fwd-id, increment fwd_packet_count
                        self.flow_buffer[self.fwd_id].fwd_packet_count += 1
                        self.flow_buffer[self.fwd_id].packet_count += 1
                        # print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                        # self.fwd_id,
                        # self.flow_buffer[self.fwd_id].packet_count,
                        # time.time() - self.start_time,
                        # self.flow_buffer[self.fwd_id].fwd_packet_count,
                        # self.flow_buffer[self.fwd_id].bwd_packet_count,
                        # self.flow_count ))
                    # use else for faster processing
                    else:
                        # only compute the bwd-id in case of bwd packet for faster processing
                        self.bwd_id =  networking.Flow.make_reverse_flow(self.current_flow)

                        # teardown is checked only in case of bwd_packet, since bwd_packet is the final FIN packet
                        # of a tcp 4-way teardown!
                        # or, a flow might end because of an rst-flag
                        # look for tcp first, since udp packets will give key-error for fin_flag!
                        if self.ip_header['protocol'] == 0x6 and (self.tcp_header['fin_flag'] or self.tcp_header['rst_flag']) == 1:
                            self.flow_buffer[self.bwd_id].duration = int((time.time() - self.flow_buffer[self.bwd_id].start_time) * 1000000)
                            
                            # put the flows that are finished into the queue and send to GUI
                            # as well as to send to the neural network for predictions
                            if self.scan_event.is_set():
                                self.q.put((self.current_flow.get_flow_id(), self.flow_buffer[self.bwd_id].duration))
                                self.gui_event.set()
                                print("Flow {0} ended with duration {1:d}!".format(self.bwd_id, self.flow_buffer[self.bwd_id].duration))

                        self.flow_buffer[self.bwd_id].bwd_packet_count += 1
                        self.flow_buffer[self.bwd_id].packet_count += 1
                        # print("{0:<46s}{1:<12d} {2:<12f} {3:<12d} {4:<12d} {5:<12d}".format(
                        # self.bwd_id,
                        # self.flow_buffer[self.bwd_id].packet_count,
                        # time.time() - self.start_time,
                        # self.flow_buffer[self.bwd_id].fwd_packet_count,
                        # self.flow_buffer[self.bwd_id].bwd_packet_count,
                        # self.flow_count ))
                # if self.scan_event.is_set():
                #     # put stuff on the queue
                #     self.q.put(self.current_flow.get_flow_id())
                #     # signal the gui to refresh with the given data
                #     self.gui_event.set()