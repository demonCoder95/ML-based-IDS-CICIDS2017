import numpy as np
from keras.models import load_model
from keras.models import Model
from sklearn import metrics

print("importing model...")
# load the saved model
model = load_model("models/portscan.h5")

# layer_name = "probability_layer"
# probability_layer_model = Model(inputs=model.input, outputs=model.get_layer(layer_name).output)

# bwd_packets/s, psh_flag_count, init_win_bytes_fwd is the order in which rows are arranged in the dataset
means = [21108.165364069184, 0.6606939019154039, 11145.127075719018]
stds = [62462.54360438435, 0.4734746587193721, 14274.27865383086]

# not_encoded = [5.010999, 6, 29200] - benign

# not_encoded = [10989, 0, 1024]  - attack
# not_encoded = [5.13375, 6, 29200] - benign

not_encoded =  [0.0565083650745529, 3, 447]

input_vector = []
# normalize the input
for i in range(0, 3):
    input_vector.append((not_encoded[i] - means[i] ) / stds[i])

# convert input to matrix form for neural network
matrix_input = np.matrix(input_vector)

# perform the prediction - get the probability matrix
print("Predicting...")
pred_prob = model.predict(matrix_input)
# get the max index
pred_index = np.argmax(pred_prob,axis=1)
# probability output
print("Result: {} with probability of {}".format(pred_index[0], pred_prob[0][pred_index[0]]))