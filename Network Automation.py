# _____________________________________________________________________________

# Nour A Sharaky
# 202000149
# NS00149@TKH.EDU.EG

# _____________________________________________________________________________

# Importing important libraries
import random 
import datetime
from paramiko import *
from time import sleep
import scapy.all as scapy

# _____________________________________________________________________________

# Storing script's start time
startTime = datetime.datetime.now()
# _____________________________________________________________________________

# Variables For Connection
hostname = ""
myUsername = "admin"
myPassword = "C1sc0@123"

#_____________________________________________________________________________

# SSH connection
def ssh_connect(hostname, myUsername, myPassword, isRouter = True):
    try:
        #Initialize and Store the SSH Object from Paramiko
        ssh = SSHClient()

        # Specifying ciphers for SSH connection
        if isRouter: 
            # Router - Compatible Ciphers
            Transport._preferred_ciphers = "aes256-cbc", "3des-cbc", " aes192-cbc", "aes256-cbc"
        else:  # Switch - Compatible Ciphers
            Transport._preferred_ciphers = 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'
        
        # Load the keys for SSH connection
        ssh.load_system_host_keys()

        # Set keys for SSH connection
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        # Connect to SSH Using the Connection Variables
        ssh.connect(hostname, username=myUsername, password=myPassword)

        # Opening the SSH shell
        shell = ssh.invoke_shell()
        
        print("SSH connection to " + hostname + " Successfull")
        return shell

    except:
        print("SSH connection to " + hostname + " Unsuccessfull - Contact an administrator")
        return None

def shell_execute(shell, myCommand):

    # Sending Configuration commands
    shell.send(myCommand)

    # Wait for 2 seconds
    sleep(2)

    # Receiving the command's response
    response = shell.recv(1000000000).decode("UTF-8")

    return response

#_____________________________________________________________________________

# Functions to change Designated Router (DR) election

def get_DR(shell, shell2):

    # Get OSPF neighbors from 2 routers
    show_ospf_neighbor = shell_execute(shell, "show ip ospf neighbor\n")
    show_ospf_neighbor2 = shell_execute(shell2, "show ip ospf neighbor\n")

    # Split each table by new lines and store in list
    ospf_neighbor_row = show_ospf_neighbor.splitlines()
    ospf_neighbor_row2 = show_ospf_neighbor2.splitlines()

    # Remove shell lines (ex. R1#)
    ospf_neighbor_row = ospf_neighbor_row[4:-1]
    ospf_neighbor_row2 = ospf_neighbor_row2[4:-1]


    # Complete OSPF routing table by comparing both neighbors' tables
    for router in ospf_neighbor_row2:
        found = False
        for router2 in ospf_neighbor_row:
            if router[0:7] in router2[0:7]:
                found = True 
                break
            else:
                continue
        if not found:
            ospf_neighbor_row.append(router)

    # Sort the new table by router ID
    ospf_neighbor_row.sort()
    
    # list to store each router's OSPF info
    OSPF = []

    # Variable to store the new DR
    DR = ""

    # Storing each router's info in a Dictionary and storing the current DR's list
    for row in ospf_neighbor_row:
        columns = row.split()

        routerOSPF = {"ID": columns[0], "priority" : columns[1], "state" : columns[2], "IP" : columns[4], "int": columns[5]}

        if "FULL/DR" in routerOSPF["state"]:
            DR = routerOSPF

        OSPF.append(routerOSPF)
    
    return DR, OSPF

def get_randomIP(DR):

    # Generate a random IP to select a new DR
    randomRouterIP = "172.16.16."+str(random.randrange(1,len(routers)))

    # Check that the randomly picked IP isn't the current DR's IP
    if DR["IP"] == randomRouterIP:
        return get_randomIP(DR)
    else:
        return randomRouterIP

def change_DR(shell, shell2):

    print("-"*50)
    print("24 Hours have passed...")
    print("NEW DESIGNATED ROUTER WILL BE SET RANDOMLY")
    print("---------------")
    print("Reseting all routers' priorities:")

    # Retreiving the DR and Routers' info dictionary
    DR, OSPF = get_DR(shell, shell2)

    # Retreving the new DR's IP
    newDR = get_randomIP(DR)

    for router in OSPF:
        # Reset all routers' priority to 1
        shell_execute(routers[router["IP"]], "conf t\ninterface g1/0\nip ospf priority 1\nip ospf network broadcast\ndo write\nend\n")
        print("Priority Reset For Router:", router["IP"])

    # Set new randomly picked DR's priority
    shell_execute(routers[newDR], "conf t\ninterface g1/0\nip ospf priority 100\nip ospf network broadcast\ndo write\nend\n")
    print("---------------")
    print("New Designated Router set:", newDR)
    print("-"*50)

    return DR, newDR, OSPF

#_____________________________________________________________________________

# Gathering PDU information
def get_packet_info(packet):

    # Retreiving the PDU's Source and Destination MAC Addresses and the PDU's type
    try:
        sourceMAC = packet[scapy.Ether].src
        DestMAC = packet[scapy.Ether].dst
        PDUtype = packet[scapy.Ether].type # ARP 0x0806 2054 | IPV4 0x0800 2048
    except:  # MAC = "aa:bb:cc:dd:ee:ff" IS UNKNOWN
        sourceMAC, DestMAC, PDUtype = "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", None
        pass

    # Retreiving the PDU's Source and Destination IP Addresses and the protocol used
    try:
        sourceIP = packet[scapy.IP].src
        DestIP =  packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto  # ospf = 89 | tcp = 6 | icmp =1 | udp = 17
    except:
        sourceIP, DestIP, protocol = None, None, None
        pass

    # Mitigation
    Threat_Detector(sourceMAC, trustedMACs, packet)

def sniffer(myFilter=""):

    # Snifffing PDUs and sending them to get_packet_info function
    scapy.sniff(iface="Microsoft KM-TEST Loopback Adapter #2",prn=get_packet_info, store=0, filter = myFilter)
    
# _____________________________________________________________________________

# Function to check if PDU is sent from trusted MAC Addresses and Trusted OSPF Domain, then sends a copy of untrusted PDUs to AI Application for further inspection
def Threat_Detector(sourceMAC, trustedMACs, packet):

    alert= ""

    # Getting the PDU's protocol
    try:  # ospf = 89
        protocol = packet[scapy.IP].proto
    except:
        protocol = None

    # Comparing MAC addresses with the trusted MAC Addresses
    if sourceMAC not in trustedMACs:
        # Detecting Untrusted OSPF PDUs and sending a copy of the PDU to VLAN 88 (172.16.88.88)
        if protocol == 89:
            alert = "UNTRUSTED OSPF PDU & UNKOWN SOURCE MAC DETECTED " + str(sourceMAC) + "\nPACKET INFO : " + str(packet)

            scapy.send(scapy.IP(dst="172.16.88.88")/scapy.ICMP()/alert,
                       verbose=0, iface="Microsoft KM-TEST Loopback Adapter #2")

            print("UNTRUSTED OSPF PDU & UNKOWN SOURCE MAC DETECTED", sourceMAC, "PACKET SENT TO AI APPLICATION FOR FURTHER INSPECTION!")
            change_vlan()
            print("\nALL ROUTERS' OPERATING VLAN HAVE CHANGED - CONTACT AN ADMINISTRATOR")
            print("~"*30)

        # sending a copy of the unknown MAC addresses PDU to VLAN 88 (172.16.88.88)
        else:
            alert = "UNKOWN SOURCE MAC DETECTED " + str(sourceMAC) + "\nPACKET INFO : " + str(packet)

            scapy.send(scapy.IP(dst="172.16.88.88")/scapy.ICMP()/alert,
                    verbose=0, iface="Microsoft KM-TEST Loopback Adapter #2")

            print("UNKOWN SOURCE MAC DETECTED", sourceMAC,"PACKET SENT TO AI APPLICATION FOR FURTHER INSPECTION!")
            change_vlan()
            print("\nALL ROUTERS' OPERATING VLAN HAVE CHANGED - CONTACT AN ADMINISTRATOR")
            print("~"*30)

# _____________________________________________________________________________

# Function to change all routers' operating VLANs when a threat is detected (VLAN 10 -> VLAN 20)
def change_vlan():
    current_vlan= shell_execute(sw_shell,"show run | b monitor session 1 source vlan\n")

    if "vlan 10" in current_vlan:
        shell_execute(sw_shell, "conf t\nint range g0/0-1, g1/0-1, g2/0-1\nno switchport access vlan 10\nswitchport access vlan 20\nexit\nmonitor session 1 source vlan 20\nend")

# Function to change back all routers' operating VLAN every 24 hours (VLAN 20 -> VLAN 10)
def revert_vlan():
    current_vlan = shell_execute(sw_shell, "show run | b monitor session 1 source vlan\n")

    if "vlan 20" in current_vlan:
        shell_execute(sw_shell, "conf t\nint range g0/0-1, g1/0-1, g2/0-1\nno switchport access vlan 20\nswitchport access vlan 10\nexit\nno monitor session 1 source vlan 20\nend")

# _____________________________________________________________________________

print("\nBOOTING SDN NETWORK THREAD")
print("-"*50)

# Starting SSH connection to all 6 routers and switches
r1_shell = ssh_connect("172.16.16.1", myUsername, myPassword)
r2_shell = ssh_connect("172.16.16.2", myUsername, myPassword)
r3_shell = ssh_connect("172.16.16.3", myUsername, myPassword)
r4_shell = ssh_connect("172.16.16.4", myUsername, myPassword)
r5_shell = ssh_connect("172.16.16.5", myUsername, myPassword)
r6_shell = ssh_connect("172.16.16.6", myUsername, myPassword)
sw_shell = ssh_connect("172.16.16.7", myUsername, myPassword, False)

print("-"*50)
try:
    # Removing pre-built configuration from switch that blocks my sniffing function
    shell_execute(sw_shell, "en\nconf t\nint g3/3\nno media-type rj45\ndo write\nend\n")
    sleep(20)
except:
    pass

# Routers' list
routers = {"172.16.16.1":r1_shell,"172.16.16.2": r2_shell,"172.16.16.3": r3_shell, "172.16.16.4":r4_shell, "172.16.16.5":r5_shell,"172.16.16.6": r6_shell}

# Trusted MAC Addresses 
trustedMACs = ["00:0c:29:9a:e1:76", "02:00:4c:4f:4f:50", "ca:02:08:53:00:1c", "ca:01:08:39:00:1c", "ca:03:08:79:00:1c", "ca:04:08:88:00:1c", "ca:05:08:97:00:1c", "ca:06:08:a6:00:1c",
               "0c:11:73:07:d7:0f", "0c:11:73:07:d7:0c", "0c:11:73:07:d7:00", "0c:11:73:07:d7:01", "0c:11:73:07:d7:04", "0c:11:73:07:d7:05", "0c:11:73:07:d7:08", "0c:11:73:07:d7:09", "0c:11:73:07:80:0a", "00:0c:29:9a:e1:80", "00:bb:60:0c:4d:d3"]

if __name__ == "__main__":

    #change DR every 24 Hours
    delta = datetime.datetime.now() - startTime

    if delta.total_seconds() >= 86400:
        try:
            change_DR(r3_shell, r4_shell)
        except:
            print("Change DR - FAILED")
        
        try:
            revert_vlan()
        except:
            print("Revert VLAN - FAILED")

        startTime = datetime.datetime.now()

    try:
        # Activate sniffer
        sniffer()
    except:
        print("Traffic monitoring - INACTIVE")

    print('x')
    

