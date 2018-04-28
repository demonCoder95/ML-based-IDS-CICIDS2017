'''
    This implements some simple structures requried for the feature
    extraction engine in the IDS
    Author: Noor Muhammad Malik
    License: None
'''

# a bidirectional flow is characterized by a 5-tuple
class Flow:
    def __init__(self,
        src_ip = "", src_port = 0, dest_ip = "", dest_port = 0, protocol = 0):
        # intrinsic flow attributes
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol
        
        # attributes important for feature extraction
        self.fwd_packet_count = 0  #num of packets in fwd direction
        self.bwd_packet_count = 0  # num of packets in bwd direction
        self.packet_count = 0 # total number of packets seen belonging to this flow
        self.start_time = 0.0 # determine the starting timestamp to determine flow duration
        self.flow_duration = 0    # the duration of flow in microseconds
        self.bwd_packets_per_second = 0.0 # a feature itself
        self.init_win_bytes_fwd = 0 # a feature itself
        self.psh_flag_count = 0 # a feature itself

    def get_flow_id(self):
        self.flow_id = "{0}-{1}-{2}-{3}-{4}".format(self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.protocol)
        return self.flow_id

    # create a reverse flow from a flow object, to identify
    # bidirectional flows
    @staticmethod
    def make_reverse_flow(flow_object):
        return "{0}-{1}-{2}-{3}-{4}".format(
            flow_object.dest_ip,
            flow_object.dest_port,
            flow_object.src_ip,
            flow_object.src_port,
            flow_object.protocol
        )
