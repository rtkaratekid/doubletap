#!/usr/bin/python3
import subprocess
import netifaces as ni
import re
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import requests
import argparse
import logging

start = time.time()
default_dirs = str(os.environ["HOME"]) + "/"
myip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']
resultQueue = multiprocessing.Queue()
#parser = argparse.ArgumentParser()
#args = parser.parse_args()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Creates a function for multiprocessing.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return


# Identify the service running on the open port and
# try basic auth attack. Service acts as a switch
def connect_to_port(ip_address, port, service):

    # make a connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))

    # get the banner from the port, we're going to assume the banner isn't tampered
    banner = s.recv(1024)
    banner = banner.decode("utf-8") #### change

    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip_address, "ftp-connect", total_communication)

    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-connect", total_communication)

    elif service == "ssh":
        total_communication = banner
        write_to_file(ip_address, "ssh-connect", total_communication)

    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner + user + password
        write_to_file(ip_address, "pop3-connect", total_communication)

    else:
        print(bcolors.WARNING + "[-]" + bcolors.ENDC + " Port service not recognized, continuing")

    s.close()  # close the connection

# Functions for writing into premade markdown templates
def write_to_file(ip_address: str, enum_type: str, data: int):

    file_path_linux = "%s%s/%s-linux-exploit-steps.md" % (dirs, ip_address, ip_address)
    file_path_windows = "%s%s/%s-windows-exploit-steps.md" % (dirs, ip_address, ip_address)
    paths = [file_path_linux, file_path_windows]
    # print(bcolors.OKGREEN + "[*] Writing " + enum_type + " to template files:\n" + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC + "\n")

    for path in paths:
        #        if enum_type == "portscan":
        #            subprocess.getoutput("replace INSERTTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "dirb":
            subprocess.getoutput("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path)
        if enum_type == "dirbssl":
            subprocess.getoutput("replace INSERTDIRBSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nikto":
            subprocess.getoutput("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ftp-connect":
            subprocess.getoutput("replace INSERTFTPTEST \"" + data + "\"  -- " + path)
        if enum_type == "smtp-connect":
            subprocess.getoutput("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "ssh-connect":
            subprocess.getoutput("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "pop3-connect":
            subprocess.getoutput("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path)
        if enum_type == "curl":
            subprocess.getoutput("replace INSERTCURLHEADER \"" + data + "\"  -- " + path)
        if enum_type == "wig":
            subprocess.getoutput("replace INSERTWIGSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wigssl":
            subprocess.getoutput("replace INSERTWIGSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "smbmap":
            subprocess.getoutput("replace INSERTSMBMAP \"" + data + "\"  -- " + path)
        if enum_type == "rpcmap":
            subprocess.getoutput("replace INSERTRPCMAP \"" + data + "\"  -- " + path)
        if enum_type == "samrdump":
            subprocess.getoutput("replace INSERTSAMRDUMP \"" + data + "\"  -- " + path)
        if enum_type == "vulnscan":
            subprocess.getoutput("replace INSERTVULNSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nfsscan":
            subprocess.getoutput("replace INSERTNFSSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ssl-scan":
            subprocess.getoutput("replace INSERTSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "parsero":
            subprocess.getoutput("replace INSERTROBOTS \"" + data + "\"  -- " + path)
        if enum_type == "sshscan":
            subprocess.getoutput("replace INSERTSSHBRUTE \"" + str(data) + "\"  -- " + path)
        if enum_type == "fulltcpscan":
            subprocess.getoutput("replace INSERTFULLTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "udpscan":
            subprocess.getoutput("replace INSERTUDPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "waf":
            subprocess.getoutput("replace INSERTWAFSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wafssl":
            subprocess.getoutput("replace INSERTWAFSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ldap":
            subprocess.getoutput("replace INSERTLDAPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "kerb":
            subprocess.getoutput("replace INSERTKERBSCAN \"" + data + "\"  -- " + path)
    return


def enumerate_http(ip_address, port, http: bool):
    protocol = "http"
    if not http:
        protocol = "https"

    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Detected {protocol} on {ip_address}:{port}, starting webapp scans for {protocol}")

    # nikto
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address, port, protocol))
    nikto_process.start()

    # parsero
    parsero_process = multiprocessing.Process(target=parsero, args=(ip_address, port, protocol))
    parsero_process.start()

    # wig
    wig_process = multiprocessing.Process(target=wig, args=(ip_address, port, protocol))
    wig_process.start()

    # waf
    waf_process = multiprocessing.Process(target=waf, args=(ip_address, port, protocol))
    waf_process.start()

    url = f"{protocol}://{ip_address}:{port}/xxxxxxx"
    response = requests.get(url)
    if response.status_code == 404:  # could also check == requests.codes.ok
        gobuster_process = multiprocessing.Process(target=gobuster, args=(ip_address, port, protocol))
        gobuster_process.start()

    else:
        print(bcolors.WARNING + "[-] Response was not 404 on port " + port + ", skipping directory scans" + bcolors.ENDC)

    return

def gobuster(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting GOBUSTER scan for {ip_address} : {port} {bcolors.ENDC}")
    DIRSCAN = f"gobuster dir -z -u {url_start}://{ip_address}:{port} -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_dir = subprocess.getoutput(DIRSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with DIRB-scan for {ip_address} {bcolors.ENDC}")
    #print(results_dirb)
    write_to_file(ip_address, "dirb", results_dir)
    return


def gobuster_ssl(ip_address, port, url_start):
    print(f'{bcolors.HEADER}[*]{bcolors.ENDC} Starting GOBUSTER SSL scan for {ip_address}:{port}')
    DIRBSCAN = f"gobuster dir -z -u {url_start}://{ip_address}:{port} -e -f -n -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_dirb = subprocess.getoutput(DIRBSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with GOBUSTER SSL-scan for {ip_address}")
    #print(results_dirb)
    write_to_file(ip_address, "dirbssl", results_dirb)
    return


## don't think this is called anywhere
def wig(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting WIG scan for {ip_address}{bcolors.ENDC}")
    WIGSCAN = f"wig-git -t 20 -u {url_start}://{ip_address}:{port} -q -d  | tee -a {dirs}{ip_address}/webapp_scans/wig-{ip_address}.txt"
    results_wig = subprocess.getoutput(WIGSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with WIG-scan for {ip_address}{bcolors.ENDC}")
    #print(results_wig)
    write_to_file(ip_address, "wig", results_wig)
    return


## don't think this is called anywhere
def wigssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting WIGSSL scan for {ip_address}{bcolors.ENDC}")
    WIGSCAN = f"wig-git -t 20 -u {url_start}://{ip_address}:{port} -q -d  | tee -a {dirs}{ip_address}/webapp_scans/wig-{ip_address}.txt"
    results_wig = subprocess.getoutput(WIGSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with WIGSSL-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "wigssl", results_wig)
    return


## don't think this is called anywhere
def parsero(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting ROBOTS scan for {ip_address}{bcolors.ENDC}")
    ROBOTSSCAN = f"parsero-git -o -u {url_start}://{ip_address}:{port} | grep OK | grep -o 'http.*'  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_parsero = subprocess.getoutput(ROBOTSSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with ROBOTS-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "parsero", results_parsero)
    return


def waf(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting WAF scan for {ip_address}{bcolors.ENDC}")
    WAFSCAN = f"wafw00f {url_start}://{ip_address}:{port} -a | tee -a {dirs}{ip_address}/webapp_scans/waf-{ip_address}.txt"
    results_waf = subprocess.getoutput(WAFSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with WAF-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "waf", results_waf)
    return


def wafssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting WAFSSL scan for {ip_address}{bcolors.ENDC}")
    WAFSSLSCAN = f"wafw00f {url_start}://{ip_address}:{port} -a | tee -a {dirs}{ip_address}/webapp_scans/waf-{ip_address}.txt"
    results_wafssl = subprocess.getoutput(WAFSSLSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with WAFSSL-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "wafssl", results_wafssl)
    return


def nikto(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting NIKTO scan for {ip_address}{bcolors.ENDC}")
    NIKTOSCAN = f"nikto -maxtime 5m -h {url_start}://{ip_address}:{port} | tee -a {dirs}{ip_address}/webapp_scans/nikto-{url_start}-{ip_address}.txt"
    results_nikto = subprocess.getoutput(NIKTOSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with NIKTO-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "nikto", results_nikto)
    return


## don't think this is called anywhere
def ssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}[*] Starting SSL scan for {ip_address}{bcolors.ENDC}")
    SSLSCAN = f"sslscan {ip_address}:{port}  |  tee {dirs}{ip_address}/webapp_scans/ssl_scan_{ip_address}"
    results_ssl = subprocess.getoutput(SSLSCAN)
    print(f"{bcolors.OKGREEN}[*] Finished with SSL-scan for {ip_address}{bcolors.ENDC}")
    write_to_file(ip_address, "ssl-scan", results_ssl)
    return


def mssql_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting MSSQL based scan for {ip_address}:{port}")
    MSSQLSCAN = f"nmap -sV -Pn -p {port} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN {dirs}{ip_address}/service_scans/mssql_{ip_address}.nmap %s"
    mssql_results = subprocess.getoutput(MSSQLSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with MSSQL-scan for {ip_address}")
    return


def smtp_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting SMTP based scan on {ip_address}:{port}")
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = f"nmap -sV -Pn -p {port} --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 {ip_address} -oN {dirs}{ip_address}/service_scans/smtp_{ip_address}.nmap"
    smtp_results = subprocess.getoutput(SMTPSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with SMTP-scan for {ip_address}")
    write_to_file(ip_address, "smtp-connect", smtp_results)
    return


def smb_scan(ip_address, port):
    #print(bcolors.HEADER + "[*] Detected SMB on " + ip_address + ":" + port)
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting SMB based scans for {ip_address}:{port}")
    SMBMAP = f"smbmap -H {ip_address} | tee {dirs}{ip_address}/service_scans/smbmap_{ip_address}"
    smbmap_results = subprocess.getoutput(SMBMAP)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with SMBMap-scan for {ip_address}")
    #print(smbmap_results)
    write_to_file(ip_address, "smbmap", smbmap_results)
    return


def rpc_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting RPC based scan on {ip_address}:{port}")
    RPCMAP = f"enum4linux -a {ip_address}  | tee {dirs}{ip_address}/service_scans/rpcmap_{ip_address}"
    rpcmap_results = subprocess.getoutput(RPCMAP)
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Finished with RPC-scan for {ip_address}")
    write_to_file(ip_address, "rpcmap", rpcmap_results)
    return


def samr_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting SAMR based scan on {ip_address}:port")
    SAMRDUMP = f"impacket-samrdump {ip_address} | tee {dirs}{ip_address}/service_scans/samrdump_{ip_address}"
    samrdump_results = subprocess.getoutput(SAMRDUMP)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with SAMR-scan for {ip_address}")
    write_to_file(ip_address, "samrdump", samrdump_results)
    return


def ftp_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting FTP based scan on {ip_address}:{port}")
    connect_to_port(ip_address, port, "ftp")

    FTPSCAN = f"nmap -sV -Pn -vv -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN {dirs}{ip_address}/service_scans/ftp_{ip_address}.nmap {ip_address}"
    ftp_results = subprocess.getoutput(FTPSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with FTP-scan for {ip_address}")
    write_to_file(ip_address, "ftp-connect", ftp_results)
    return


def ldap_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting LDAP based scan on {ip_address}:{port}")
    LDAPSCAN = f"nmap --script ldap* -p 389 {ip_address}-oN {dirs}{ip_address}/service_scans/ldap_{ip_address}.nmap {ip_address}"
    ldap_results = subprocess.getoutput(LDAPSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with LDAP-scan for {ip_address}")
    write_to_file(ip_address, "ldap", ldap_results)
    return


def kerb_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting KERBEROS basd scan on {ip_address}:{port}")
    KERBSCAN = f'DOM=$(nmap -p {port} --script krb5-enum-users {ip_address} | grep report | cut -d " " -f 5) && nmap -p {port} --script krb5-enum-users --script-args krb5-enum-users.realm=$DOM {ip_address} -oN {dirs}{ip_address}/service_scans/kerberos_{ip_address}.nmap {ip_address}'
    kerb_results = subprocess.getoutput(KERBSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with KERBEROS-scan for {ip_address}")
    write_to_file(ip_address, "kerb", kerb_results)
    return


def nfs_scan(ip_address, port):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting NFS based scan on {ip_address}")
    SHOWMOUNT = f"showmount -e {ip_address} | tee {dirs}{ip_address}/service_scans/nfs_{ip_address}.nmap"
    nfsscan_results = subprocess.getoutput(SHOWMOUNT)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with NFS-scan for {ip_address}")
    write_to_file(ip_address, "nfsscan", nfsscan_results)
    return


def ssh_scan(ip_address, port):
    print("{bcolors.HEADER}[*]{bcolors.ENDC} Starting SSH based scan on {ip_address}:{port}")
    connect_to_port(ip_address, port, "ssh")
    ssh_process = multiprocessing.Process(target=quick_hit_ssh, args=(ip_address, port))
    ssh_process.start()
    return


# function to do a short brute force of ssh
def quick_hit_ssh(ip_address, port):
    print("{bcolors.HEADER}[*]{bcolors.ENDC} Starting SSH Bruteforce on {ip_address}:{port}")
    SSHSCAN = f"sudo hydra -I -C /opt/doubletap-git/wordlists/quick_hit.txt  -t 3 ssh://{ip_address} -s {port} | grep target"
    results_ssh = subprocess.getoutput(SSHSCAN)
    print("{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with SSH-Bruteforce check for {ip_address}:{port}")
    # print results_ssh
    write_to_file(ip_address, "sshscan", results_ssh)
    return


## don't think this is called anywhere
def pop3Scan(ip_address, port):
    print("{bcolors.HEADER}[*]{bcolors.ENDC} Starting POP3 scan on {ip_address}:{port}")
    connect_to_port(ip_address, port, "pop3")
    return


## don't think this is called anywhere
def nmap_vuln_scan(ip_address):
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Running Vulnerability based nmap scans for {ip_address}")
    VULN = f"nmap -sV --script=vuln --script-timeout=600 -p {ports} {ip_address} -oN {dirs}{ip_address}/port_scans/vuln_{ip_address}.nmap"
    vuln_results = subprocess.getoutput(VULN)
    print("{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with VULN-scan for {ip_address}")
    #print(vuln_results)
    write_to_file(ip_address, "vulnscan", vuln_results)
    return


def full_tcp_scan(ip_address):
    print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Running FULL TCP nmap scan on '{ip_address}'")
    TCPALL = f"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 {ip_address} | tee {dirs}{ip_address}/port_scans/fulltcp_{ip_address}.nmap"
    tcp_results = subprocess.getoutput(TCPALL)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with FULL-TCP-scan for {ip_address}")
    print(tcp_results)
    write_to_file(ip_address, "fulltcpscan", tcp_results)
    return


def partial_udp_scan(ip_address):
    print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Running UDP nmap scan on {ip_address}")
    UDPSCAN = f"sudo nmap -Pn -A -sC -sU -T 4 --top-ports 20 -oN {dirs}{ip_address}/port_scans/udp_{ip_address}.nmap {ip_address}"
    udpscan_results = subprocess.getoutput(UDPSCAN)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with UDP-scan for {ip_address}")
    print(udpscan_results)
    write_to_file(ip_address, "udpscan", udpscan_results)
    return

# takes output directly from unicornscan
# returns a dict of protocols and the port they run on
def parse_unicornscan(result:str)->dict:
    port_protocol = {}
    lines = result.split("\n")
    for line in lines:
        ports = [];
        port = 0;
        protocol = "";
        tokens = line.split(" ")
        for t in tokens:
            if "[" in t:
                protocol = t.split("[")[0]
            elif "]" in t:
                port = int(t.split("]")[0])
        if protocol in port_protocol:
            # add to the list of ports in the dict
            port_protocol[protocol].append(port)
        else:
            # initialize a list for that protocol
            ports.append(port)
            port_protocol[protocol] = ports

    return port_protocol


def unicornTcpScan(ip_address, q):
    print(bcolors.OKGREEN + f"[*] Running Full Unicornscan on {ip_address}, this may take a few mintues" + bcolors.ENDC)
    TCPALL = f"sudo unicornscan -mT {ip_address}:a | tee {ip_address}{dirs}/port_scans/fulltcp_{ip_address}.uni"
    open_ports = subprocess.getoutput(TCPALL)
    print(bcolors.OKGREEN + "[*] Finished with FULL-TCP-scan for " + ip_address + bcolors.ENDC)
    #print(open_ports)
    write_to_file(ip_address, "fulltcpscan", open_ports)
    ports_dirty = ",".join(re.findall('\[(.*?)\]', open_ports))
    clean_ports = ports_dirty.replace(' ', '')
    q.put((parse_unicornscan(open_ports), clean_ports)) # returning a tuple for the two different purposes
    return


def vulnEnumForUni(ip_address: str ,ports: str):
    if not ports.strip(" "):
        print("{bcolors.FAIL}\nNo ports open for nmap vulnscan\n {bcolors.ENDC}") 
        return
    print(bcolors.OKGREEN + "[*] Running Vulnerability based nmap scans for " + ip_address + bcolors.ENDC)
    VULN = f"nmap -sV --script=vuln --script-timeout=600 -p {ports} {ip_address} -oN {dirs}{ip_address}/port_scans/vuln_{ip_address}.nmap"
    vuln_results = subprocess.getoutput(VULN)
    print(bcolors.OKGREEN + "[*] Finished with VULN-scan for " + ip_address + bcolors.ENDC)
    #print(vuln_results)
    write_to_file(ip_address, "vulnscan", vuln_results)
    return

# Starting funtion to parse and pipe to multiprocessing
def portScan(ip_address, unicornscan, resultQueue):
    ip_address = ip_address.strip()
    print(f"\n{bcolors.OKGREEN}[*]{bcolors.ENDC} Current default output directory set as: '{dirs}'")
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Host IP set as: '{myip}'\n")

    ### Do the portscan!
    if(unicornscan):
        # do the full unicornscan stuff
        m = multiprocessing.Process(target=unicornTcpScan, args=(scanip,resultQueue,))
        m.start()

        # get unicornScan output tuple, queue is used in case we want to add udp scan as well
        tcp_output = resultQueue.get()

        # run targeted nmap on the open ports
        l = multiprocessing.Process(target=vulnEnumForUni, args=(scanip, tcp_output[1],))
        l.start()

        serv_dict = tcp_output[0]

    else:
        # use nmap top 1000 to generate quick list and do more complete scans
        l = multiprocessing.Process(target=partial_udp_scan, args=(scanip,))
        l.start()
        m = multiprocessing.Process(target=full_tcp_scan, args=(scanip,))
        m.start()
        print(f"{bcolors.OKBLUE}[*]{bcolors.ENC} Running Quick TCP nmap scans for: {ip_address}")
        TCPSCAN = f"nmap -sV -Pn --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        # TCPSCAN = f"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        #TCPSCAN = f"nmap -sV -Pn -O --top-ports 100 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        results = subprocess.getoutput(TCPSCAN)
        #print(results)      
        print(bcolors.OKGREEN + "[*] Finished with QUICK-TCP-scans for " + ip_address + ". Starting secondary scans" + bcolors.ENDC)
        #print(results)
        
        #    write_to_file(ip_address, "portscan", results)
        lines = results.split("\n")
        serv_dict = {}
        for line in lines:
            ports = []
            line = line.strip()
            if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
                while "  " in line:
                    line = line.replace("  ", " ");
                linesplit = line.split(" ")
                service = linesplit[2]  # grab the service name

                port = line.split(" ")[0]  # grab the port/proto
                if service in serv_dict:
                    ports = serv_dict[service]  # if the service is already in the dict, grab the port list

                ports.append(port)
                serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)

    # Search through the service dictionary to call additional targeted enumeration functions
    for (serv, ports) in serv_dict.items():
       
        # Do http scan
        if serv == "http" or serv == "http-proxy" or serv == "http-alt" or serv == "http?" or serv == "http-proxy?":
            for port in ports:
                port = port.split("/")[0]
                multProc(enumerate_http, ip_address, port, true)

        # Do https scan
        elif (serv == "ssl/http") or ("https" == serv) or ("https?" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(enumerate_http, ip_address, port, false)

        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtp_scan, ip_address, port)

        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftp_scan, ip_address, port)

        elif "microsoft-ds" in serv or serv == "netbios-ssn":
            for port in ports:
                port = port.split("/")[0]
                multProc(smb_scan, ip_address, port)
                multProc(rpc_scan, ip_address, port)
                multProc(samr_scan, ip_address, port)

        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssql_scan, ip_address, port)

        elif "rpcbind" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(nfs_scan, ip_address, port)

        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ssh_scan, ip_address, port)

        elif "ldap" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ldap_scan, ip_address, port)

        elif "kerberos-sec" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(kerb_scan, ip_address, port)
    return


print(bcolors.HEADER)
print("------------------------------------------------------------")
print("!!!!                     DOUBLETAP                     !!!!!")
print("!!!!                A script kiddies delite            !!!!!")
print("!!!!  An all in one recon and target template creator  !!!!!")
print("!!!!            Automagically runs the following       !!!!!")
print("!!!!     gobuster, nikto, ftp, ssh, mssql, pop3, tcp   !!!!!")
print("!!!!           udp, smtp, smb, wig, hydra              !!!!!")
print("------------------------------------------------------------")
print(bcolors.ENDC)

if not os.geteuid()==0:
    sys.exit('This script must be run with sudo!')
elif len(sys.argv) < 2:
    print("")
    print("Usage: python3 doubletap.py -t <ip> <ip> -i <interface> -o /home/Desktop/")
    print("Example: python doubletap.py -t 192.168.1.101 192.168.1.102 -i tun0")
    print("Current default output directory set as " + default_dirs)
    print("Host IP set as " + myip)
    print("")
    sys.exit()

parser = argparse.ArgumentParser()

#-t target(s) -n -o ~/Desktop -i eth:0
parser.add_argument("-t", "--target(s)", dest = "targets", default = "", help="IP address of target(s) separated by spaces")
parser.add_argument("-u", "--unicorn", dest = "unicorn", action="store_true", help="use unicornscan instead of nmap")
parser.add_argument("-o", "--output",dest ="output", help="absolute filepath to output dir")
parser.add_argument("-i", "--interface",dest = "interface", help="interface to use, default is eth0")


args = parser.parse_args()

if args.output:
    dirs = args.output
else:
    dirs = "/home/" + str(os.environ["SUDO_USER"]) + "/Desktop/"

if args.interface:
    myip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
else:
    myip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']

if args.unicorn:
    unicorn = True
else:
    unicorn = False


def setup_target_directory(dirs, scanip, myip):
    print(f"{bcolors.WARNING}[-]{bcolors.ENDC} No folder was found for '{scanip}'. Setting up folder: {dirs}{scanip}")
    subprocess.getoutput("mkdir " + dirs + scanip)
    subprocess.getoutput("mkdir " + dirs + scanip + "/exploits")
    subprocess.getoutput("mkdir " + dirs + scanip + "/privesc")
    subprocess.getoutput("mkdir " + dirs + scanip + "/service_scans")
    subprocess.getoutput("mkdir " + dirs + scanip + "/webapp_scans")
    subprocess.getoutput("mkdir " + dirs + scanip + "/port_scans")

    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Folder created here: '{dirs}{scanip}'")
    subprocess.getoutput("cp /opt/doubletap-git/templates/windows-template.md " + dirs + scanip + "/" + scanip + "-windows-exploit-steps.md")
    subprocess.getoutput("cp /opt/doubletap-git/templates/linux-template.md " + dirs + scanip + "/" + scanip + "-linux-exploit-steps.md")
    subprocess.getoutput("cp /opt/doubletap-git/templates/windows-worksheet-template.md " + dirs + scanip + "/" + scanip + "-windows-notes.md")
    subprocess.getoutput("cp /opt/doubletap-git/templates/linux-worksheet-template.md " + dirs + scanip + "/" + scanip + "-linux-notes.md")

    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Added pentesting templates to: '{dirs}{scanip}'")
    subprocess.getoutput(f"sed -i -e 's/INSERTIPADDRESS/{scanip}/g' {dirs}{scanip}/{scanip}-windows-exploit-steps.md")
    subprocess.getoutput(f"sed -i -e 's/MYIPADDRESS/{myip}/g' {dirs}{scanip}/{scanip}-windows-exploit-steps.md")
    subprocess.getoutput(f"sed -i -e 's/INSERTIPADDRESS/{scanip}/g' {dirs}{scanip}/{scanip}-linux-exploit-steps.md")
    subprocess.getoutput(f"sed -i -e 's/MYIPADDRESS/{myip}/g' {dirs}{scanip}/{scanip}-linux-exploit-steps.md")

if __name__ == '__main__':
    #multiprocessing.log_to_stderr(logging.DEBUG)

    targets = args.targets.split(" ")

    for scanip in targets:
        scanip = scanip.rstrip()

        # if we don't have a directory for it already, set one up
        if not scanip in subprocess.getoutput(f"ls {dirs}"):
            setup_target_directory(dirs, scanip, myip)

        p = multiprocessing.Process(target=portScan, args=(scanip,unicorn,resultQueue))
        time.sleep(1)  # Just a nice wait for unicornscan
        p.start()
