from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import smtplib
from tkinter import messagebox
from pymongo import MongoClient

# Thresholds for attack detection
PORT_SCAN_THRESHOLD = 10  
DDOS_THRESHOLD = 100       


port_scan_tracker = defaultdict(list)
ddos_tracker = defaultdict(list)

def log_attack(attack_type, src_ip, details):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    report = f"[{timestamp}] Attack Detected: {attack_type}\n"
    report += f"Source IP: {src_ip}\n"
    report += f"Details: {details}\n"
    report += "-" * 50 + "\n"

    with open("ids_report.txt", "a") as f:
        f.write(report)

    print(report) 

def detect_attack(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()

        # Detecting Port Scanning
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            port_scan_tracker[src_ip].append((dst_port, current_time))
            port_scan_tracker[src_ip] = [(port, t) for port, t in port_scan_tracker[src_ip] if current_time - t < 1]
            if len(set(port for port, _ in port_scan_tracker[src_ip])) > PORT_SCAN_THRESHOLD:
                log_attack("Port Scanning", src_ip, f"Accessed {len(set(port for port, _ in port_scan_tracker[src_ip]))} different ports rapidly.")
                myclient = MongoClient(
                    "mongodb+srv://jainam:7sjssduBdkrndj@finalproject.q4jsbp.mongodb.net/Ransomware?retryWrites=true&w=majority&appName=finalproject",
                    tls=True, 
                    tlsAllowInvalidCertificates=True
                    )
                mydb = myclient["IDS"]
                mycol = mydb["machines"]
                myquery = { "ipaddress": "192.168.1.2" }
                newvalues = { "$set": { "status": "Attack" } }
                mycol.update_one(myquery, newvalues)     
                s = smtplib.SMTP('smtp.gmail.com', 587)
                s.starttls()
                s.login("emailid through which alert is send@gmail.com", "password")
                subject="IDS-Alert!!!"
                message = "Your system with the IP Address 192.168.1.2 is under attack."
                text=f"Subject: {subject}\n\n{message}"
                s.sendmail("emailid through which alert is send@gmail.com", "emailid on which alert is sent@gmail.com", text)
                print("Mail alert sent")
                s.quit()
                messagebox.showwarning("IDS Alert!!!", "Your system has been Attacked (Port Scanning Detected)")
                return

        # Detecting DDoS Attack
        ddos_tracker[src_ip].append(current_time)
        ddos_tracker[src_ip] = [t for t in ddos_tracker[src_ip] if current_time - t < 1]
        if len(ddos_tracker[src_ip]) > DDOS_THRESHOLD:
            log_attack("DDoS Attack", src_ip, f"Sent {len(ddos_tracker[src_ip])} packets in 1 second.")
            myclient = MongoClient(
                    "mongodb+srv://jainam:7sjssduBdkrndj@finalproject.q4jsbp.mongodb.net/Ransomware?retryWrites=true&w=majority&appName=finalproject",
                    tls=True, 
                    tlsAllowInvalidCertificates=True
                    )
            mydb = myclient["IDS"]
            mycol = mydb["machines"]
            myquery = { "ipaddress": "192.168.1.2" }
            newvalues = { "$set": { "status": "Attack" } }
            mycol.update_one(myquery, newvalues)     
            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login("emailid through which alert is send@gmail.com", "password")
            subject="IDS-Alert!!!"
            message = "Your system with the IP Address 192.168.1.2 is under attack."
            text=f"Subject: {subject}\n\n{message}"
            s.sendmail("emailid through which alert is send@gmail.com", "emailid on which alert is sent@gmail.com", text)
            print("Mail alert sent")
            s.quit()
            messagebox.showwarning("IDS Alert!!!", "Your system has been Attacked (DOS Attack Detected)")
            return

    print("No Attack Detected")

# Starting the IDS
print("Starting IDS...")
sniff(filter="ip", prn=detect_attack, store=False)
