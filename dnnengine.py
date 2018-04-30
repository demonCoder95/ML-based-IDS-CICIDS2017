"""
    This is the core of the DNN prediction engine for the IDS which will work in conjunction with 
    other modules to give good predictions on the traffic
    Author: Noor Muhammad Malik
    Date: April 28, 2018
    License: None
"""

# standard imports
import numpy as np
from keras.models import load_model
from keras.models import Model
from sklearn import metrics

class DNNEngine():
    def __init__(self, attacks_list, dnn_ready_event, engine_dnn_queue, dnn_gui_queue, gui_event):
        
        # keep the 'stuff'
        self.attacks_list = attacks_list
        self.engine_dnn_queue = engine_dnn_queue
        self.dnn_gui_queue = dnn_gui_queue
        self.gui_event = gui_event

        # load all the models
        self.models = dict()
        self.models["portscan"] = load_model("models/portscan.h5")

        # put in some normalization data
        self.means = dict()
        self.stds = dict()
        
        # bwd_packets/s, psh_flag_count, init_win_bytes_fwd
        self.means['portscan'] = [21108.165364069184, 0.6606939019154039, 11145.127075719018]
        self.stds['portscan'] = [62462.54360438435, 0.4734746587193721, 14274.27865383086]

        # signal that the model is ready
        dnn_ready_event.set()

    def run_dnn_engine(self):
        while True:
            # wait for the data on the queue
            raw_data = self.engine_dnn_queue.get()
            # get portscan features out of the dictionary
            flow_id = raw_data['portscan'][0]
            portscan_features = raw_data['portscan'][1:]
            input_vector = []
            # normalize the features
            for i in range(0, 3):
                input_vector.append((portscan_features[i] - self.means['portscan'][i])/self.stds['portscan'][i])
            # convert to np.array for neural net
            matrix_input = np.matrix(input_vector)
            # perform the prediction
            print("[DEBUG-DNN] predicting...")
            pred_prob = self.models["portscan"].predict(matrix_input)
            pred_index = np.argmax(pred_prob, axis=1)
            if pred_index[0] == 0:
                print("[DEBUG-DNN] ATTACK: {}%".format(pred_prob[0][pred_index[0]]*100))
                # GUI only needs attack traffic flows
                self.dnn_gui_queue.put((flow_id, "ATTACK"))
                self.gui_event.set()
            else:
                print("[DEBUG DNN] BENIGN: {}%".format(pred_prob[0][pred_index[0]]*100))
                # self.dnn_gui_queue.put((flow_id, "BENIGN"))
                # self.gui_event.set()