import pandas as pd
import numpy as np

import tools

print("[DEBUG] importing libs")

from sklearn.model_selection import train_test_split
from sklearn import metrics
from keras.models import Sequential
from keras.models import load_model

from keras.layers.core import Dense, Activation
from keras.callbacks import EarlyStopping

print("[DEBUG] dataset loading...")

# read in the dataset
path = "/home/noor/Documents/data/portscan.csv"
# read features of only portscan traffic
dataset = pd.read_csv(path, usecols=["Init_Win_bytes_forward", " Bwd Packets/s", " PSH Flag Count", " Label"])

print("[DEBUG] dataset loading done")

# eliminate empty rows (if any)
dataset.dropna(inplace=True, axis=1)

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

print("[DEBUG] generating the DNN model")

# Create neural net
model = Sequential()
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(50, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(1, kernel_initializer='normal', name="probability_layer"))
model.add(Dense(y.shape[1],activation='softmax'))
model.compile(loss='categorical_crossentropy', optimizer='adam')
monitor = EarlyStopping(monitor='val_loss', min_delta=1e-3, patience=3, verbose=1, mode='auto')

print("[DEBUG] training the model")
# train the model
model.fit(x_train,y_train,validation_data=(x_test,y_test),callbacks=[monitor],verbose=2,epochs=1000)

model.save("portscan.h5")

# del model

# model = load_model("portscan.h5")

# # evaluate the model for accuracy
# pred = model.predict(x_test)
# pred = np.argmax(pred,axis=1)
# print(pred)
# y_eval = np.argmax(y_test,axis=1)
# score = metrics.accuracy_score(y_eval, pred)
# print("Validation score: {0:.2f}%".format(score*100))




