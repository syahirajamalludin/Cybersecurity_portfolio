# PCAP Analysis – "It's a Trap!" (2018-07-20) 
## Tools Used - Wireshark 
## Steps Taken:
1. Opened PCAP in Wireshark
2. Checked **Protocol Hierarchy** – saw abnormal DNS & HTTP traffic
3. Looked at **Conversations** – one external IP dominated traffic
4. Followed **TCP Stream** – found HTTP GET request downloading `setup.exe`
  
## Findings - Multiple DNS queries to suspicious domains - HTTP request to download executable file - Likely malware delivery attempt from fake software site

<img width="940" height="95" alt="image" src="https://github.com/user-attachments/assets/8188d805-9370-4b5e-af39-70cb88279528" />

<img width="940" height="170" alt="image" src="https://github.com/user-attachments/assets/5375cb6f-11f5-4214-ab6d-7f02a61417ad" />

<img width="940" height="91" alt="image" src="https://github.com/user-attachments/assets/a1fd14fc-78e0-4a01-8336-6f153490812f" />



