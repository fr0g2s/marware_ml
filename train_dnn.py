# common
import os,sys
import numpy as np
# keras
from keras import layers
from keras import models
from keras import metrics
from keras import losses
from keras import optimizers
from keras import datasets              
from keras.utils import np_utils
from keras.layers import Dropout
# scikit-learn
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix

# start
print("[*] Start Training Model...")

# data preprocessing
datasets = np.loadtxt('features.csv', delimiter=',',skiprows=1)  # skip => exclude header
xy_data = datasets   
train_set, test_set = train_test_split(xy_data, test_size=0.1)   
print('Training Length : ', len(train_set), 'Test Length : ', len(test_set))

# train data
x_train_data = train_set.T[1:]
y_train_data = train_set.T[:1]

# test data
x_test_data = test_set.T[1:]
y_test_data = test_set.T[:1]

input_len = x_train_data.shape[0]

# modeling start
model = models.Sequential()

# input layer
model.add(layers.Dense(input_len, activation='relu', input_shape=(input_len,)))

# hidden layer
model.add(layers.Dense(20, activation='relu'))
model.add(layers.Dense(20, activation='relu'))


# output layer
model.add(layers.Dense(1, activation='sigmoid'))  

model.compile(optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy'])  

hist = model.fit(x_train_data.T, y_train_data.T, epochs=250, batch_size=50)

# Confusion Matrix    ####
y_pred_data = model.predict(x_test_data.T)
y_pred_data = [round(x[0]) for x in y_pred_data]

print("")
print("# Confusion Matrix # ")
cm = confusion_matrix(y_test_data.T, y_pred_data)
print(cm)

print("")
print("# Test Result # ")
performace_test = model.evaluate(x_test_data.T, y_test_data.T, batch_size=50)
print('Test Accuracy ->', performace_test[1])


