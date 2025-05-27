from scapy.all import ARP, Ether, srp
from pymongo import MongoClient
import time
import tkinter as tk
from tkinter import messagebox


client = MongoClient('mongodb+srv://jainam:7sjssduBdkrndj@finalproject.q4jsbp.mongodb.net/Ransomware?retryWrites=true&w=majority&appName=finalproject')  
db = client['IDS'] 
collection = db['machines']  


def scan_network():
    target_ip = "192.168.32.0/24"  
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def add_to_database(devices):
    for device in devices:
        ip = device['ip']

        existing = collection.find_one({"ipaddress": ip})
        if not existing:
         
            record = {
                "name": "User",
                "ostype": "windows",
                "ipaddress": ip,
                "status": "safe"
            }
            collection.insert_one(record)
            print(f"Added to DB: {record}")
        else:
            print(f"IP {ip} already exists in the database.")


def check_for_attack():
    myquery = { "status": "Attack" }
    while True:
        time.sleep(3)
        my_doc = collection.find_one(myquery)
        if my_doc is None:
            print("No Attack. Will scan again in 3 seconds...")
            print("Scanning the network...")
            devices = scan_network()
            print(f"Found Devices: {devices}")
            add_to_database(devices)
            continue
        else:
            ipaddress = my_doc.get('ipaddress', '0.0.0.0')

            root = tk.Tk()
            root.withdraw() 
            messagebox.showwarning("IDS - Alert!!!", f"Machine with IP Address: {ipaddress} has been attacked!")            
            break
    print("Alerting system ended")


def main():
    while True:
        print("Scanning the network...")
        devices = scan_network()
        print(f"Found Devices: {devices}")
        add_to_database(devices)
        check_for_attack()
        time.sleep(10) 

if __name__ == "__main__":
    main()
