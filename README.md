<hr>

NOUR SHARAKY - 2020000149 - NS00149@tkh.edu.eg

Coventry University - The Knowledge Hub Universities branch - Bsc of Ethical Hacking and Cybersecurity - Level 5.

KH5064CEM Networks - Coursework 

<hr>

The network automation tool:
1. Establishes SSH connection to 6 routers and a core switch.
2. Starts monitoring network traffic and extracts PDU information, such as:
    - Source MAC Address
    - Destination MAC Address
    - PDU Type (ARP, IPV4..)
    - Source IP Address
    - Destination IP Address
    - Protocol Used
2. Compares Source MAC addresses with trusted MAC addresses in the network (routers’ and switch’s MAC Addresses)
3. Verifies that routing PDUs originate from the trusted OSPF domain
4. If any PDU does not comply and is considered unknown, it is detected as a threat.
5. Once a threat is detected:
    - A copy of the detected PDU is sent to the AI Application for further inspection 
    - The routers’ operating VLAN is changed to another randomly available VLAN.
    
 <hr>
