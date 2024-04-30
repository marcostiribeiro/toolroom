#
#Application developed to detect DDoS attacks using Machine Learning.
######################## Detection Module ######################## 

import pickle5 as pickle
from builtins import print
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from os import path
import os
import sys
import subprocess
import socket
import requests
from getmac import get_mac_address as gma
import json
from datetime import datetime
import iptc


headers = {
    'Content-Type': 'application/json',
}

def _load_config_file():
    try:
        with open("Config.json", 'r') as file_handler:
            return json.load(file_handler)
    except:
        return json.load(sys.stdin)

class sensor:
    
    def __init__(self) -> None:
        self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        self.id_sensor = 0
        self.dpid = ""
        self.__counter_packet = 0
        self.hostname = socket.gethostname()
        self.list_ip_black_list = dict()
        self.loop = True
        usr_config = _load_config_file()
        self.service = usr_config["service"]
        self.type = usr_config["type"]
        if self.service == "remote":
            if self.type == "resume":
                self.model = self.select_model(usr_config["model"])
                self.interfaceLan = usr_config["interface"]
                self.interface_controller = usr_config["interface_controller"]
                self.server_ip = usr_config["server"]
                self.servers = usr_config["servers"]        
                self.login = usr_config["login"]
                self.passwd = usr_config["password"]            
                self.url_server_connect = usr_config["url_server_connect"]
                self.url_server_set_ip = usr_config["url_server_set_ip"]
                self.conect_server(self.login, self.passwd, self.interface_controller )
            elif (self.type == "probabilistic") and (usr_config["RF"] == "RF" or usr_config["NN"] == "NN") :
                self.model = self.select_model(usr_config["model"])
                self.interfaceLan = usr_config["interface"]
                self.interface_controller = usr_config["interface_controller"]
                self.server_ip = usr_config["sdn"]
                self.servers = usr_config["servers"]        
                self.login = usr_config["login"]
                self.passwd = usr_config["password"]            
                self.url_server_connect = usr_config["url_server_connect"]
                self.url_server_set_ip = usr_config["url_server_set_ip"]
                self.conect_server(self.login, self.passwd, self.interface_controller )
            else:
                print("Configuration error")
                sys.exit()
        elif  self.service == "local":
            self.model = self.select_model(usr_config["model"])
            self.interfaceLan = usr_config["interface"]
            self.servers = usr_config["servers"]      
        else:
            print("Configuration error")
            sys.exit()
        self.linecount = usr_config["linecount"]
        self.show_detect = eval(usr_config["show_detect"])
        self.generate_report = eval(usr_config["generate_report"])
        if self.linecount:
            self.linecount = self.linecount
        else:
            self.linecount = 600
        self.flow_file = open(self.ROOT_DIR + "/assets/files/logs/" + "flow_file.txt", "w+")

    def get_counter_packet(self):
        return self.__counter_packet

    def add_counter_packet(self):
        self.__counter_packet += 1
    
    #
    # Method for connecting to security server
    #

    def conect_server(self, name_sensor,password_sensor, interface):
        mac_address = gma(interface)
        data = {'sensor': name_sensor,
                'senha': password_sensor,
                'mac_address': mac_address,
                'host_name': self.hostname}
        url_post = 'http://' + self.server_ip + self.url_server_connect
        response = requests.post(url_post, headers=headers, json=data)
        result = response.json()
        if (result['access'] == False):
            print('Access denied')
            sys.exit()
        else:
            self.id_sensor = result['id']
            self.dpid = result['dpid']
    #
    # Add IP on the list detected malicions IP
    # Generate report
    # Shows malicious IP detected

    def add_ip_black_list(self, ip):
        if self.show_detect:
            print("\033[2;31;43m",ip,"\033[0;0m")      
        if  self.generate_report:
            try:
                data_hour = datetime.now()
                print(data_hour)
                f = open("report.txt", "a")
                f.write(f'{ip} {self.list_ip_black_list[ip]} {data_hour} \n')
                f.close()
            except Exception as e:
                print("Error writing to file")
        if ip in self.list_ip_black_list:
            temp_count = self.list_ip_black_list[ip]
            temp_count += 1
            self.list_ip_black_list[ip] = temp_count 
            return False
        else:
            self.list_ip_black_list[ip] = 1
            return True
    #
    # Method that sends IPs identified as malicious
    #
    def send_ip_detect_from_ip(self, ip):
        mac_address = gma(self.interface_controller)
        data = {'id': self.id_sensor,
                'A': self.login,
                'B': mac_address,
                'C': ip,
                'D': self.__counter_packet,
                'E' : self.hostname}
        self.add_counter_packet()
        url_post = 'http://' + self.server_ip + self.url_server_set_ip
        response = requests.post(url_post, headers=headers, json=data)
        result = response.json()

        print(result['D'])
        print(self.__counter_packet)
        if result['D'] == self.__counter_packet:
            print("successful connection ")
            self.add_counter_packet()
        else:
            print('Access Denied')
            sys.exit()

    #
    # Method that sends ips and the probability of being malicious
    #
    def send_ip_detect_prob(self, ip, prob):
        mac_address = gma(self.interface_controller)
        data = {'id': self.id_sensor,
                'A': self.login,
                'B': mac_address,
                'C': ip,
                'D': self.__counter_packet,
                'f': prob}
        self.add_counter_packet()
        url_post = 'http://' + self.server_ip + self.url_server_set_ip
        response = requests.post(url_post, headers=headers, json=data)
        result = response.json()

        print(result['D'])
        print(self.__counter_packet)

        if result['D'] == self.__counter_packet:
            print("successful connection ")
            self.add_counter_packet()
        else:
            print('access denied')
            sys.exit()
    #
    # Block ip in local firewall
    #
    def block_ip(self, ip):
        rule = iptc.Rule()
        rule.src = ip
        rule.target = iptc.Target(rule, "DROP")
        self.chain.insert_rule(rule)
    
    def main(self):
        while self.loop:
            try:
                self.capture_packet_network()
                self.teste_network_data()
                os.remove(self.ROOT_DIR + "/assets/files/pcap/out.pcap")
            except ValueError as exception:
                if exception.args[0] == "short":
                    print("Insufficient data flow")

    #
    #  Capture pcap packet
    #
    def capture_packet_network(self):
        pcap_file = open(self.ROOT_DIR + "/assets/files/pcap/out.pcap", "w", encoding="ISO-8859-1")
        pcap_list = self.proc_capture_pcap(self.interfaceLan, self.linecount)
        pcap_file.writelines(pcap_list)
        pcap_file.close()
        self.proc_run_cic()

    #
    # Process for packet capture
    #

    def proc_capture_pcap(self, interface: str, line_count: int = 5000):
        pcap = ["tcpdump", "-i", interface, "-s", "65535", "-w", "-"]
        process = subprocess.Popen(
            pcap,
            stdout=subprocess.PIPE,
            universal_newlines=False,
            encoding="ISO-8859-1",
        )
        ctr = 0
        list = []
        while ctr < line_count:
            ln = process.stdout.readline()
            list.append(ln)
            ctr += 1
        process.stdout.close()
        exit_status = process.wait()
        if exit_status:
            raise subprocess.CalledProcessError(exit_status, pcap)
        return list

    #
    # Running CFM
    #
    def proc_run_cic(self):
        cic_cmd = ["sh", "cfm", self.ROOT_DIR + "/assets/files/pcap", self.ROOT_DIR + "/assets/files/flowOut"]
        cic_process = subprocess.Popen(
            cic_cmd,
            cwd=self.ROOT_DIR + "/assets/files/CFM/bin",
            stdout=subprocess.DEVNULL,
        )
        status = cic_process.wait()
        if status:
            raise subprocess.CalledProcessError(status, cic_cmd)

    #
    # Transform pcap file
    #

    def tranform_data(self):
        uri = self.ROOT_DIR + "/assets/files/flowOut/out.pcap_Flow.csv"
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
    # Teste flow
    #

    def teste_network_data(self):
        try:
            flow_data = self.tranform_data()
        except ValueError:
            raise ValueError("short")
        flow_features = flow_data["data"]
        metadata = flow_data["metadata"]

        if self.service == "remote":
            predictions = self.model[1].predict(flow_features)
            if self.type == "resume":
                for row, prediction in zip(metadata.values, predictions):
                    from_ip, to_ip, proto, from_port, to_port = row
                    if prediction:
                        if to_ip in self.servers:
                            if self.add_ip_black_list(from_ip):
                                self.send_ip_detect_from_ip(from_ip)
                                break
            elif self.type == "probabilistic":
                predictions_proba  = self.model[1].predict_proba(flow_features)
                for row, prediction, proba in zip(metadata.values, predictions,predictions_proba):
                    from_ip, to_ip, proto, from_port, to_port = row
                    if prediction:
                        if to_ip in self.servers:
                            if self.add_ip_black_list(from_ip):
                                self.send_ip_detect_prob(from_ip, proba)
                                break
        elif self.service == "local":
            predictions = self.model[1].predict(flow_features)
            for row, prediction in zip(metadata.values, predictions):
                from_ip, to_ip, proto, from_port, to_port = row
                if prediction:
                    print(from_ip)
                    if to_ip in self.servers:
                        if self.add_ip_black_list(from_ip):
                            self.block_ip(from_ip)
                            break
                        
    #
    # Checks if there is already a trained model and
    # select the model
    #      
    def select_model(self,_model):

        if 'RF' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "RF_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/RF_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                print("Model not found, run training module.")
        if 'GNB' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "GNB_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/GNB_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                print("Model not found, run training module.")

        if 'SVM' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "SVM_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/SVM_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                print("Model not found, run training module.")

        if 'NN' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "NN_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/NN_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model
            else:
                print("Model not found, run training module.")

        if 'SC' in _model:
            if path.exists(self.ROOT_DIR + "/assets/model/" + "StackingClassifier_model.pck"):
                model_file = open(self.ROOT_DIR + "/assets/model/StackingClassifier_model.pck", "rb")
                model = pickle.load(model_file)
                print("********* Selected Model    **********")
                print(model[0])
                print("**************************************")
                model_file.close()
                return model

            else:
                print("Model not found, run training module.")

        
        ## Your mode here,
        ## if 'xx' in model:
       
      
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
    #Load config dataset
    #
    def load_df(self, uri):

        if (uri != self.ROOT_DIR + "/assets/dataset/dtddos.csv"):
            input_df = pd.read_csv(self.ROOT_DIR + "/assets/files/flowOut/out.pcap_Flow.csv")
            return input_df       

    #
    # pre-processed the dataframe
    # delete unused fields
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
    sensors.main()

if __name__ == "__main__":
    
    start()


