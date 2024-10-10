from flask import Flask, jsonify
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
import firebase_admin
from firebase_admin import credentials, firestore
import threading

app = Flask(__name__)

# Initialize Firebase Admin SDK
cred = credentials.Certificate("firebase-service-account.json")  # Add the path to your serviceAccountKey.json
firebase_admin.initialize_app(cred)
db = firestore.client()

# Dictionary to hold the MAC addresses
mac_addresses = {}

# Function to process packets and extract MAC addresses
def packet_handler(packet):
    if packet.haslayer(Dot11):
        mac_addr = packet.addr2
        print(f"Packet captured: {packet.summary()}")  # Print packet summary debugging
        if mac_addr not in mac_addresses:
            mac_addresses[mac_addr] = True
            print(f"New MAC address detected: {mac_addr}")
            # Save the MAC address to Firebase
            save_mac_address(mac_addr)

# Function to save MAC address to Firebase Firestore
def save_mac_address(mac_addr):
    doc_ref = db.collection("devices").document(mac_addr)
    doc_ref.set({
        'mac_address': mac_addr,
        'detected': True
    })

# Function to start sniffing in a separate thread
def start_sniffing():
    sniff(prn=packet_handler, iface="Wi-Fi", store=0)

# API endpoint to return the count of unique devices
@app.route('/device-count', methods=['GET'])
def get_device_count():
    return jsonify({'device_count': len(mac_addresses)})

# API endpoint to return MAC addresses
@app.route('/mac-addresses', methods=['GET'])
def get_mac_addresses():
    return jsonify({'mac_addresses': list(mac_addresses.keys())})

# Start the sniffing thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
