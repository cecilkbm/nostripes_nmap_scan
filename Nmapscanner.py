#!/usr/bin/python3

import nmap   #imports nmap module into python script

nscan = nmap.PortScanner()  
p_start = 20    #port range start 
p_end = 700     #port range end

print("\nA Basic Nmap Automation Tool\nby NostripesZebra")
print('\n---------------****************-------------')
print('---------------*******NSZ********-------------')

ip_addr = input("\nPlease enter the ip address you want to scan: ")  #user ip entry
print("The ip address you entered is: ", ip_addr)   #user input verification
type(ip_addr)

resp = input("""\nPlease Enter Scan Type
                1) SYN ACK Scan
                2) UPD Scan
                3) Comprehensive Scan (Ports 20 - 700)\n""")

print("You have selected: ", resp)

if resp == '1':
    print("Nmap Version: ", nscan.nmap_version())        #displays nmap version 
    nscan.scan(ip_addr, '1-1024', '-v -sS')              #scan ip_address ports
    print(nscan.scaninfo())
    print("Ip Stat: ", nscan[ip_addr].state())
    print(nscan[ip_addr].all_protocols())
    print("Open Ports: ", nscan[ip_addr]['tcp'].keys())

elif resp == '2':
    print("Nmap Version: ", nscan.nmap_version())
    nscan.scan(ip_addr, '1-1024', '-v -sU')
    print(nscan.scaninfo())
    print("Ip Stat: ", nscan[ip_addr].state())
    print(nscan[ip_addr].all_protocols())
    print("Open Ports: ", nscan[ip_addr]['udp'].keys())

elif resp == '3':
    print("Nmap Version: ", nscan.nmap_version())
    nscan.scan(ip_addr, '20-700', '-v -sS -sC -sV -A -O')
    print(nscan.scaninfo())
    print("Ip Stat: ", nscan[ip_addr].state())
    print(nscan[ip_addr].all_protocols())
    for i in range(p_start,p_end+1):
        res = nscan.scan(ip_addr,str(i))               
        res = res['scan'][ip_addr]['tcp'][i]['state']
        print(f'port {i} is {res}.')                      #print output PORT STATUS
    

elif resp >= '4':
    print("You have entered an invalid input, Please Try Again.")

