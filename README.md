#AI Threat Detector



\## Overview

AI Threat Detector is a real-time, AI-powered network monitoring tool that captures live network traffic, detects anomalies, and displays them on a live web dashboard. It simulates a mini Security Operations Center (SOC), combining cybersecurity, machine learning, and automation.



\## Features

\- \*\*Live Packet Capture:\*\* Uses Scapy to capture live network packets including IPs, ports, protocol, and packet length.

\- \*\*Anomaly Detection:\*\* Detects suspicious traffic in real-time using an Isolation Forest model.

\- \*\*Console Alerts:\*\* Prints alerts for suspicious packets as they are captured.

\- \*\*Live Dashboard:\*\* Flask-based dashboard that visualizes all captured packets and highlights anomalies.

\- \*\*Real-Time Detection:\*\* Suspicious packets are immediately flagged in both console and dashboard.



\## Technologies

\- \*\*Python 3\*\*

\- \*\*Scapy\*\* – for network packet capture

\- \*\*pandas\*\* – for data handling and feature extraction

\- \*\*scikit-learn\*\* – Isolation Forest for anomaly detection

\- \*\*Flask\*\* – real-time web dashboard






