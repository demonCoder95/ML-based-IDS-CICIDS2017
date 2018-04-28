import pandas as pd
import numpy as np

import tools

print("[DEBUG] importing libs")

from sklearn.model_selection import train_test_split
from sklearn import metrics
from keras.models import Sequential
from keras.models import load_model
from keras.models import Model

from keras.layers.core import Dense, Activation
from keras.callbacks import EarlyStopping

print("[DEBUG] dataset loading...")

# read in the dataset
path = "/home/noor/Documents/data/portscan.csv"
# read features or only portscan and benign traffic
dataset = pd.read_csv(path, usecols=["Init_Win_bytes_forward"," Bwd Packets/s", " PSH Flag Count", " Label"])

print("[DEBUG] dataset loading done")

# eliminate empty rows (if any)
dataset.dropna(inplace=True, axis=0)

print("[DEBUG] feature encoding in progress")

# encode the features corresponding to the feature type
tools.encode_numeric_zscore(dataset, "Init_Win_bytes_forward")
tools.encode_numeric_zscore(dataset, " Bwd Packets/s")
tools.encode_numeric_zscore(dataset, " PSH Flag Count")

# tools.encode_numeric_zscore(dataset, " Bwd Packet Length Min")
# tools.encode_numeric_zscore(dataset, " Subflow Fwd Bytes")
# tools.encode_numeric_zscore(dataset, "Total Length of Fwd Packets")

tools.encode_text_index(dataset, " Label")

print("[DEBUG] feature encoding done")

# create the DNN model
# split dataset into features and labels for the network
x, y = tools.to_xy(dataset,' Label')
# make test and train data for cross-validation
x_train, x_test, y_train, y_test = train_test_split(
    x, y, test_size=0.90, random_state=42)

model = load_model("../portscan.h5")

layer_name = "probability_layer"

probability_layer_model = Model(inputs=model.input, outputs=model.get_layer(layer_name).output)
print("probability output")
probability_layer_model.predict(x_test)

# evaluate the model for accuracy
# x_test is a 6xn matrix, 6 features for each sample
# pred is a 2xn matrix, 2 label probabilities for each sample
pred = model.predict(x_test)
# a row vector
# pred = np.argmax(pred,axis=1)

print("Class output")
print(pred)
# a row vector
# y_eval = np.argmax(y_test,axis=1)
# print(y_eval)
# score = metrics.accuracy_score(y_eval, pred)
# print("Validation score: {0:.2f}%".format(score*100))




