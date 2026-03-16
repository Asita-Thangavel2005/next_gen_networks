NetWatch — Network Monitor & QoS Analyser

A real-time network monitoring and security dashboard built with Python and Flask.  
Discover devices on your network, monitor connection quality, and detect unknown devices — all from a sleek web dashboard.


Features:
Device Scanner
- Scans all devices connected to your network
- Displays IP address, MAC address, hostname, and device type
- Detects and flags unknown/rogue devices
- Whitelist trusted devices for security monitoring

QoS Monitor
- Real-time latency, jitter, and packet loss tracking
- Live graphs updated every 3 seconds
- QoS score per target (0–100)
- Add custom targets (e.g. your router IP)
- Monitors Google DNS, Cloudflare, OpenDNS by default

Security Alerts
- Automatically alerts when an unknown device joins the network
- Logs device IP, MAC address, and timestamp
- Clear and manage alerts from the dashboard


Tech Stack:
Python 3.11, Flask 
Scapy, Socket 
HTML, CSS, JavaScript 


Project Structure:
network-monitor/
├── app.py                  → Flask backend, API routes
├── scanner.py              → Network device scanning logic
├── qos_monitor.py          → Latency & QoS tracking logic
├── requirements.txt        → Python dependencies
├── .gitignore              → Git ignore rules
├── README.md               → Project documentation
└── templates/
      └── index.html        → Dashboard UI


Setup & Installation:
Prerequisites
- Windows 10/11
- Python 3.8 or higher → https://www.python.org/downloads
- Npcap (for network scanning) → https://npcap.com/#download


Installation Steps:
1)Create a virtual environment:
python -m venv venv
2)Activate the virtual environment:
venv\Scripts\activate
3)Install dependencies
pip install -r requirements.txt
4)Install Npcap
- Download from https://npcap.com/#download
- During install, check "Install Npcap in WinPcap API-compatible mode"
- Restart your PC after installing
5)Running the App
python app.py
6)Open your browser and go to:
http://127.0.0.1:5000


