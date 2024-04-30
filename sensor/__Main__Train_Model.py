## Application developed to detect DDoS attacks using Machine Learning.
######################## Training Module ######################## 

import pickle5 as pickle
from builtins import print
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os
from os import path
# import sys


# headers = {
#     'Content-Type': 'application/json',
# }
class sensor:

    def __init__(self) -> None:
        self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.model = self.create()

    #
    # Transform pcap file
    #

    def tranform_flow_data(self):
        uri = self.ROOT_DIR + "/assets/files/flow_output/out.pcap_Flow.csv"
        dataframe = self.load_df(uri)
        metadata = pd.DataFrame()
        metadata["from_ip"] = dataframe["Src IP"]
        metadata["to_ip"] = dataframe["Dst IP"]
        metadata["protocol"] = dataframe["Protocol"]
        metadata["from_port"] = dataframe["Src Port"]
        metadata["to_port"] = dataframe["Dst Port"]
        self.pre(dataframe)
        x_train, x_test, _, _ = self.train_test(dataframe)
        data = np.concatenate((x_test, x_train))
        return {"data": data, "metadata": metadata}

    #
    # Create Models
    #

    def create(self):
        uri = self.ROOT_DIR + "/assets/dataset/dataset_ddos.csv"
        if path.exists(self.ROOT_DIR + "/assets/model/" + "RF_model.pck"):
            print("Random Forest - Start")
            type_ml = "RF"
            from sklearn.ensemble import RandomForestClassifier
            model_file = open(self.ROOT_DIR + "/assets/model/RF_model.pck", "wb")
            model = RandomForestClassifier(max_depth=2, random_state=0)
            dataframe = self.pre(self.load_df(uri))
            x_train, x_test, y_train, y_test = self.train_test(dataframe)
            model.fit(x_train, y_train)
            rf = [type_ml, model]
            pickle.dump(rf, model_file)
            model_file.close()
            print("Random Forest - End")
        if path.exists(self.ROOT_DIR + "/assets/model/" + "SVM_model.pck"):
            print("Support vector machine - Start")
            type_ml = "SVM"
            from sklearn.svm import LinearSVC
            model_file = open(self.ROOT_DIR + "/assets/model/SVM_model.pck", "wb")
            model = LinearSVC(random_state=1234, max_iter=100)
            dataframe = self.pre(self.load_df(uri))
            x_train, x_test, y_train, y_test = self.train_test(dataframe)
            model.fit(x_train, y_train)
            svm = [type_ml, model]
            pickle.dump(svm, model_file)
            model_file.close()
            print("Support vector machine - End")
        if path.exists(self.ROOT_DIR + "/assets/model/" + "GNB_model.pck"):
            print("Gaussina Naive Bayes - Start")
            type_ml = "GNB"
            from sklearn.naive_bayes import GaussianNB
            model_file = open(self.ROOT_DIR + "/assets/model/GNB_model.pck", "wb")
            model = GaussianNB()
            dataframe = self.pre(self.load_df(uri))
            x_train, x_test, y_train, y_test = self.train_test(dataframe)
            model.fit(x_train, y_train)
            gnb = [type_ml, model]
            pickle.dump(gnb, model_file)
            model_file.close()
            print("Gaussina Naive Bayes - End")

        if path.exists(self.ROOT_DIR + "/assets/model/" + "NN_model.pck"):
            type_ml = "NN"
            print("redes neurais - Start")
            from sklearn.neural_network import MLPClassifier
            model_file = open(self.ROOT_DIR + "/assets/model/NN_model.pck", "wb")
            model = MLPClassifier(hidden_layer_sizes=(10, 10, 10), max_iter=10,random_state=0)
            dataframe = self.pre(self.load_df(uri))
            x_train, x_test, y_train, y_test = self.train_test(dataframe)
            model.fit(x_train, y_train)
            nn = [type_ml, model]
            pickle.dump(nn, model_file)
            model_file.close()
            print("Redes Neurais - End")

        if path.exists(self.ROOT_DIR + "/assets/model/" + "StackingClassifier_model.pck"):
            print("Stacking Classifier - Start")
            type_ml = "ALL"
            from sklearn.ensemble import StackingClassifier
            from sklearn.linear_model import LogisticRegression
            model_file = open("RF_model.pck", "rb")
            model = pickle.load(model_file)
            model_rf = model[1]
            print(model_rf)
            model_file.close()
            model_file = open("GNB_model.pck", "rb")
            model = pickle.load(model_file)
            model_gnb = model[1]
            model_file.close()
            model_file = open("SVM_model.pck", "rb")
            model = pickle.load(model_file)
            model_svm = model[1]
            print(model_svm)
            model_file.close()
            model_file = open("NN_model.pck", "rb")
            model = pickle.load(model_file)
            model_nn = model[1]
            print(model_nn)
            model_file.close()
            estimators = [('rf', model_rf),
                            ('svm', model_svm),
                            ('gnb', model_gnb),
                            ('nn', model_nn)]

            train_test_file = open(self.ROOT_DIR + "/assets/model/StackingClassifier_model.pck", "wb")
            model_all = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression())
            dataframe = self.pre(self.load_df(uri))
            x_train, x_test, y_train, y_test = self.train_test(dataframe)
            model_all.fit(x_train, y_train)

            all = [type_ml, model_all]

            pickle.dump(all, train_test_file)
            train_test_file.close()
            print("Stacking Classifier - end")

        ##YOUR MODELO HERE
    #
    # Split data traine and test
    #

    def train_test(self, dataframe):
        x_data = []
        y_data = []

        for row in dataframe.values:
            x_data.append(row[:-1])
            y_data.append(row[-1])

        x_train, x_test, y_train, y_test = train_test_split(x_data, y_data, random_state=1, test_size=0.10)
        return np.array(x_train), np.array(x_test), np.array(y_train), np.array(y_test)

    #
    # Load dataframe
    #

    def load_df(self, uri):     
        chunksize = 1000
        list_of_dataframes = []
        for df in pd.read_csv(uri, chunksize=chunksize, nrows=6472647, index_col=0, low_memory=False):
            list_of_dataframes.append(df)
        ddos_dados = pd.concat(list_of_dataframes)
        features = ddos_dados.columns
        list_of_dataframes = []
        for df in pd.read_csv(uri, chunksize=chunksize, nrows=6321980, index_col=0, skiprows=6472647,
                              low_memory=False):
            list_of_dataframes.append(df)
        benign_dados = pd.concat(list_of_dataframes)
        benign_dados.columns = features
        dataframe = pd.concat([ddos_dados, benign_dados])
        return dataframe

    #
    # Preprocessing the dataframe
    #
    def pre(self, dataframe):
        dataframe.drop(["Flow ID", "Timestamp", "Src IP", "Dst IP", "Flow Byts/s", "Flow Pkts/s"],
                       inplace=True, axis=1, )
        dataframe["Label"] = dataframe["Label"].apply(lambda x: 1 if x == "ddos" else 0)
        for col in dataframe.columns:
            dataframe[col] = np.nan_to_num(dataframe[col])
        return dataframe

def start():
    sensors = sensor()
if __name__ == "__main__":
    start()


