import os
import hashlib
import socket
import mysql.connector as mssql
import os, sys
from time import sleep
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix
import seaborn as sns
def getMachine_addr():
	os_type = sys.platform.lower()
	command = "wmic bios get serialnumber"
	return os.popen(command).read().replace("\n","").replace("	","").replace(" ","")

def getUUID_addr():
	os_type = sys.platform.lower()
	command = "wmic path win32_computersystemproduct get uuid"
	return os.popen(command).read().replace("\n","").replace("	","").replace(" ","")

def extract_command_result(key,string):
    substring = key
    index = string.find(substring)
    result = string[index + len(substring):]
    result = result.replace(" ","")
    result = result.replace("-","")
    return result

def get_ip_address_of_host():
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        mySocket.connect(('10.255.255.255', 1))
        myIPLAN = mySocket.getsockname()[0]
    except:
        myIPLAN = '127.0.0.1'
    finally:
        mySocket.close()
    return myIPLAN
    
def save_model():
    global model
    model = '../Model/intrusion_model.pkl'
    if os.path.exists(model):
        return True
    else:
        return False

def train():
    # Define a dictionary mapping attack types to integer values
    attack_type_mapping = {
        'Data_of_Attack_Back': 1,
        'Data_of_Attack_Back_BufferOverflow': 2,
        'Data_of_Attack_Back_FTPWrite': 3,
        'Data_of_Attack_Back_GuessPassword': 4,
        'Data_of_Attack_Back_Neptune': 5,
        'Data_of_Attack_Back_NMap': 6,
        'Data_of_Attack_Back_Normal': 7,
        'Data_of_Attack_Back_PortSweep': 8,
        'Data_of_Attack_Back_RootKit': 9,
        'Data_of_Attack_Back_Satan': 10,
        'Data_of_Attack_Back_Smurf': 11
    }
    dataset = pd.read_csv('../Dataset/dataset.csv')  # Replace 'your_dataset.csv' with your dataset file path
    print('Loading Dataset...')
    # Convert attack_type to integer based on the dictionary mapping
    dataset['attack_type'] = dataset['attack_type'].map(attack_type_mapping)
    # Separate features and target variable
    X = dataset.loc[:, :' dst_host_srv_rerror_rate']
    y = dataset['attack_type']
    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    imputer = SimpleImputer(strategy='mean')
    X_train_imputed = imputer.fit_transform(X_train)
    X_test_imputed = imputer.transform(X_test)
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    sleep(3)
    print('Training Started')
    sleep(3)
    rf_classifier.fit(X_train, y_train)
    train_accuracy = rf_classifier.score(X_train, y_train)
    test_accuracy = rf_classifier.score(X_test, y_test)
    # Save the model to a .pkl file
    sleep(3)
    print('Training Complete')
    with open('../Model/intrusion_model.pkl', 'wb') as f:
        pickle.dump(rf_classifier, f)
    plt.bar(['Training', 'Test'], [train_accuracy, test_accuracy], color=['blue', 'green'])
    plt.title('Accuracy of Intrusion Model')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.savefig('../Plots/accuracy.png')
    y_pred = rf_classifier.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, cmap='Blues', fmt='g', cbar=False)
    plt.xlabel('Predicted labels')
    plt.ylabel('True labels')
    plt.title('Confusion Matrix')
    plt.savefig('../Plots/confusion_matrix.png')
    print('Models Saved')
    sleep(3)
    return "Training Complete"

 
def md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()
def key_validate(str):
    conn = mssql.connect(
        user='root', password='root', host='localhost', database='intrusion'
        )
    cur = conn.cursor()
    private_key = extract_command_result("SerialNumber",getMachine_addr()) + extract_command_result("UUID",getUUID_addr())
    if private_key in str:
        cur.execute("select * from SOFTKEY where private_key = %s and public_key = %s",(md5(private_key),md5(extract_command_result(private_key,str))))
        data=cur.fetchone()
        if data:
            return True
        else:
            return False
    else:
        return False
