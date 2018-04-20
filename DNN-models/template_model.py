import pandas as pd
import numpy as np
import tools

from sklearn.model_selection import train_test_split
from sklearn import metrics
from keras.models import Sequential
from keras.layers.core import Dense, Activation
from keras.callbacks import EarlyStopping

# read in the dataset
path = "/home/noor/Documents/FYP/dataset/<dataset>.csv"
dataset = pd.read_csv(path, usecols=["array of features to read"])

# eliminate empty rows (if any)
dataset.dropna(inplace=True, axis=0)

# encode the features corresponding to the feature type
tools.encode_numeric_zscore(dataset, "<numeric feature>")
tools.encode_text_index(dataset, "<label column>")

# create the DNN model
# split dataset into features and labels for the network
x, y = tools.to_xy(dataset,'<label column>')
# make test and train data for cross-validation
x_train, x_test, y_train, y_test = train_test_split(
    x, y, test_size=0.25, random_state=42)

# Create neural net
model = Sequential()
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(50, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(1, kernel_initializer='normal'))
model.add(Dense(y.shape[1],activation='softmax'))
model.compile(loss='categorical_crossentropy', optimizer='adam')
monitor = EarlyStopping(monitor='val_loss', min_delta=1e-3, patience=3, verbose=1, mode='auto')

# train the model
model.fit(x_train,y_train,validation_data=(x_test,y_test),callbacks=[monitor],verbose=2,epochs=1000)

# evaluate the model for accuracy
pred = model.predict(x_test)
pred = np.argmax(pred,axis=1)
y_eval = np.argmax(y_test,axis=1)
score = metrics.accuracy_score(y_eval, pred)
print("Validation score: {}%".format(score*100))


