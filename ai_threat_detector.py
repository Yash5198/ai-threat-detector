from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from flask import Flask, render_template_string
from sklearn.ensemble import IsolationForest
import threading
app = Flask(__name__)
packet_list = []
def ip_to_int(ip):
    if isinstance(ip, int):
        return ip
    parts = str(ip).split('.')
    return int(parts[0])*(256**3) + int(parts[1])*(256**2) + int(parts[2])*256 + int(parts[3])
columns = ['src_ip_num','dst_ip_num','protocol_num','length','src_port','dst_port']
dummy_df = pd.DataFrame([[0,0,0,0,0,0]], columns=columns)
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(dummy_df)
def packet_callback(packet):
    global packet_list
    packet_info = {}
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['protocol'] = packet[IP].proto
        packet_info['length'] = len(packet)        
        if TCP in packet or UDP in packet:
            packet_info['src_port'] = packet.sport
            packet_info['dst_port'] = packet.dport
        else:
            packet_info['src_port'] = 0
            packet_info['dst_port'] = 0        
        src_ip_num = ip_to_int(packet_info['src_ip'])
        dst_ip_num = ip_to_int(packet_info['dst_ip'])
        df_temp = pd.DataFrame([[src_ip_num, dst_ip_num, packet_info['protocol'], packet_info['length'],
                                 packet_info['src_port'], packet_info['dst_port']]],
                               columns=columns)      
        prediction = model.predict(df_temp)[0]
        packet_info['anomaly'] = prediction
        packet_list.append(packet_info)      
        if prediction == -1:
            print(f"⚠️ Suspicious Packet Detected! {packet_info}")
        else:
            print(f"Normal Packet: {packet_info}")
@app.route("/")
def home():
    if packet_list:
        df = pd.DataFrame(packet_list)
        def highlight_anomaly(row):
            color = 'red' if row['anomaly'] == -1 else 'black'
            return ['color: {}'.format(color)]*len(row)
        styled_df = df.style.apply(highlight_anomaly, axis=1)
        return render_template_string("""
            <h2>Live Packet Dashboard</h2>
            {{ table|safe }}
        """, table=styled_df.to_html())
    else:
        return "<h2>No packets captured yet!</h2>"
threading.Thread(target=lambda: sniff(prn=packet_callback, store=False), daemon=True).start()
if __name__ == "__main__":
    print("Starting AI Threat Detector... Visit http://127.0.0.1:5000/ for dashboard")
    app.run(debug=True)

