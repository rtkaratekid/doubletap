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
    p = multiprocessing.Process(target=targetin, args=(scan_name, scan, port))
    jobs.append(p)
    p.start()
    return

replace_keys = ["{urlstart}", "{ip_address}", "{port}", "{dirs}"]

## Replace the target IP Address and Dirs
## Further tailoring will be needed for things that need ports and urlstart
def set_scan_target_and_output(scans: dict, ip_address: str, dirs: str)-> dict:
    ret = {}
    for (key, value) in scans.items():
        temp = value.replace("{ip_address}", ip_address)
        temp = temp.replace("{dirs}", dirs)
        ret[key] = temp
    return ret

scans = {
    "ssl_scan":"sslscan {ip_address}:{port}  |  tee {dirs}{ip_address}/webapp_scans/ssl_scan_{ip_address}",
    "mssql_scan":"nmap -sV -Pn -p {port} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN {dirs}{ip_address}/service_scans/mssql_{ip_address}.nmap",
    "smtp_scan":"nmap -sV -Pn -p {port} --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 {ip_address} -oN {dirs}{ip_address}/service_scans/smtp_{ip_address}.nmap",
    "smb_scan":"smbmap -H {ip_address} | tee {dirs}{ip_address}/service_scans/smbmap_{ip_address}",
    "rpc_scan":"enum4linux -a {ip_address}  | tee {dirs}{ip_address}/service_scans/rpcmap_{ip_address}",
    "samr_scan":"impacket-samrdump {ip_address} | tee {dirs}{ip_address}/service_scans/samrdump_{ip_address}",
    "ftp_scan":"nmap -sV -Pn -vv -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN {dirs}{ip_address}/service_scans/ftp_{ip_address}.nmap {ip_address}",
    "ldap_scan":"nmap --script ldap* -p 389 {ip_address}-oN {dirs}{ip_address}/service_scans/ldap_{ip_address}.nmap {ip_address}",
    "kerb_scan":'DOM=$(nmap -p {port} --script krb5-enum-users {ip_address} | grep report | cut -d " " -f 5) && nmap -p {port} --script krb5-enum-users --script-args krb5-enum-users.realm=$DOM {ip_address} -oN {dirs}{ip_address}/service_scans/kerberos_{ip_address}.nmap {ip_address}',
    "nfs_scan":"showmount -e {ip_address} | tee {dirs}{ip_address}/service_scans/nfs_{ip_address}.nmap",
    "quick_hit_ssh":"sudo hydra -I -C /opt/doubletap-git/wordlists/quick_hit.txt  -t 3 ssh://{ip_address} -s {port} | grep target",
    "nmap_vuln_scan":"nmap -sV --script=vuln --script-timeout=600 -p {ports} {ip_address} -oN {dirs}{ip_address}/port_scans/vuln_{ip_address}.nmap",
    "full_tcp_scan":"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 {ip_address} | tee {dirs}{ip_address}/port_scans/fulltcp_{ip_address}.nmap",
    "quick_tcp_scan":"nmap -sV -Pn --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap",
    "partial_udp_scan":"sudo nmap -Pn -A -sC -sU -T 4 --top-ports 20 -oN {dirs}{ip_address}/port_scans/udp_{ip_address}.nmap {ip_address}",
    "unicornscan_full_tcp":"sudo unicornscan -mT {ip_address}:a | tee {ip_address}{dirs}/port_scans/fulltcp_{ip_address}.uni"
}


# Functions for writing into premade markdown templates
# TODO: change the markdown files such that you can use use the scan names listed above as the keys to replace text.
# This will dramatically reduce the size of this function
def write_scan_to_file(ip_address: str, enum_type: str, data: int):

    file_path_linux = f"{dirs}{ip_address}/{ip_address}-linux-exploit-steps.md"
    file_path_windows = f"{dirs}{ip_address}/{ip_address}-windows-exploit-steps.md"
    paths = [file_path_linux, file_path_windows]

    for path in paths:
        #        if enum_type == "portscan":
        #            subprocess.getoutput("replace INSERTTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "gobuster":
            subprocess.getoutput("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path)
        if enum_type == "gobuster_ssl":
            subprocess.getoutput("replace INSERTDIRBSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wig":
            subprocess.getoutput("replace INSERTWIGSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wig_ssl":
            subprocess.getoutput("replace INSERTWIGSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "parsero":
            subprocess.getoutput("replace INSERTROBOTS \"" + data + "\"  -- " + path)
        if enum_type == "waf":
            subprocess.getoutput("replace INSERTWAFSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wafssl":
            subprocess.getoutput("replace INSERTWAFSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nikto":
            subprocess.getoutput("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ssl_scan":
            subprocess.getoutput("replace INSERTSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "smtp_scan":
            subprocess.getoutput("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "smb_scan":
            subprocess.getoutput("replace INSERTSMBMAP \"" + data + "\"  -- " + path)
        if enum_type == "rpc_scan":
            subprocess.getoutput("replace INSERTRPCMAP \"" + data + "\"  -- " + path)
        if enum_type == "samr_scan":
            subprocess.getoutput("replace INSERTSAMRDUMP \"" + data + "\"  -- " + path)
        if enum_type == "ftp_scan":
            subprocess.getoutput("replace INSERTFTPTEST \"" + data + "\"  -- " + path)
        if enum_type == "ldap_scan":
            subprocess.getoutput("replace INSERTLDAPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "kerb_scan":
            subprocess.getoutput("replace INSERTKERBSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nfs_scan":
            subprocess.getoutput("replace INSERTNFSSCAN \"" + data + "\"  -- " + path)
        if enum_type == "quick_hit_ssh":
            subprocess.getoutput("replace INSERTSSHBRUTE \"" + str(data) + "\"  -- " + path)
        if enum_type == "nmap_vuln_scan":
            subprocess.getoutput("replace INSERTVULNSCAN \"" + data + "\"  -- " + path)
        if enum_type == "full_tcp_scan":
            subprocess.getoutput("replace INSERTFULLTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "partial_udp_scan":
            subprocess.getoutput("replace INSERTUDPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ssh-connect":
            subprocess.getoutput("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "pop3-connect":
            subprocess.getoutput("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path)
        if enum_type == "curl":
            subprocess.getoutput("replace INSERTCURLHEADER \"" + data + "\"  -- " + path)
    return

def run_scan(scan_name: str, scan_command: str):
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting {scan_name} for {ip_address}")
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Full command:\n\t{scan_command}")
    results = subprocess.getoutput(scan_command)
    write_scan_to_file(ip_address, scan_name, results)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with {scan_name} for {ip_address}, wrote results to report")

def run_scan_port(scan_name: str, scan_command: str, port: str):
    new_command = scan_command.replace("{port}", port)
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting {scan_name} for {ip_address}")
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Full command:\n\t{new_command}")
    results = subprocess.getoutput(new_command)
    write_scan_to_file(ip_address, scan_name, results)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with {scan_name} for {ip_address}, wrote results to report")

def run_scan_urlstart(scan_name: str, scan_command: str, urlstart: str):
    new_command = scan_command.replace("{urlstart}", urlstart)
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting {scan_name} for {ip_address}")
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Full command:\n\t{scan_command}")
    results = subprocess.getoutput(new_command)
    write_scan_to_file(ip_address, scan_name, results)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with {scan_name} for {ip_address}, wrote results to report")

def run_scan_port_urlstart(scan_name: str, scan_command: str, port: str, urlstart: str):
    new_command = scan_command.replace("{urlstart}", urlstart)
    new_command = new_command.replace("{port}", port)
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Starting {scan_name} for {ip_address}")
    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Full command:\n\t{scan_command}")
    results = subprocess.getoutput(new_command)
    write_scan_to_file(ip_address, scan_name, results)
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Finished with {scan_name} for {ip_address}, wrote results to report")


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


## helper for enumerate_http
def set_port_and_protocol(scans: dict, port: str, protocol: str)-> dict:
    ret = {}
    for (key, value) in scans.items():
        temp = value.replace("{port}", port)
        temp = temp.replace("{protocol}", urlstart)
        ret[key] = temp
    return ret

def enumerate_http(ip_address, port, http: bool):
    protocol = "http"
    if not http:
        protocol = "https"

    print(f"{bcolors.HEADER}[*]{bcolors.ENDC} Detected {protocol} on {ip_address}:{port}, starting webapp scans for {protocol}")

    http_scans = {
        "gobuster":"gobuster dir -z -u {urlstart}://{ip_address}:{port} -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt",
        "gobuster_ssl":"gobuster dir -z -u https://{ip_address}:{port} -e -f -n -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt",
        "nikto":"nikto -maxtime 5m -h {urlstart}://{ip_address}:{port} | tee -a {dirs}{ip_address}/webapp_scans/nikto-{urlstart}-{ip_address}.txt",
        "parsero":"parsero-git -o -u {urlstart}://{ip_address}:{port} | grep OK | grep -o 'http.*'  | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt",
        "wig":"wig-git -t 20 -u {urlstart}://{ip_address}:{port} -q -d  | tee -a {dirs}{ip_address}/webapp_scans/wig-{ip_address}.txt",
        "waf":"wafw00f {urlstart}://{ip_address}:{port} -a | tee -a {dirs}{ip_address}/webapp_scans/waf-{ip_address}.txt"
    }

    custom_http_scans = set_scan_target_and_output(http_scans, ip_address, dirs)
    custom_http_scans = set_port_and_protocol(custom_scans, port, protocol)

    for (key, value) in custom_http_scans.items():
        process = multiprocessing.Process(target=run_scan, args=(key, value))

    url = f"{protocol}://{ip_address}:{port}/xxxxxxx"
    response = requests.get(url)
    if response.status_code == 404:  # could also check == requests.codes.ok
        gobuster_process = multiprocessing.Process(target=run_scan, args=("gobuster", custom_http_scans["gobuster"]))
        gobuster_process = multiprocessing.Process(target=run_scan, args=("gobuster_ssl", custom_http_scans["gobuster_ssl"]))
        gobuster_process.start()

    else:
        print(bcolors.WARNING + "[-] Response was not 404 on port " + port + ", skipping directory scans" + bcolors.ENDC)

    return

# Starting funtion to parse and pipe to multiprocessing
def portScan(ip_address, unicornscan, resultQueue, custom_scans):
    ip_address = ip_address.strip()
    print(f"\n{bcolors.OKGREEN}[*]{bcolors.ENDC} Current default output directory set as: '{dirs}'")
    print(f"{bcolors.OKGREEN}[*]{bcolors.ENDC} Host IP set as: '{myip}'\n")
   
    # Do portscans
    # use nmap top 1000 to generate quick list and do more complete scans
    l = multiprocessing.Process(target=run_scan, args=("partial_udp_scan", custom_scans["partial_udp_scan"]))
    l.start()
    l = multiprocessing.Process(target=run_scan, args=("full_tcp_scan", custom_scans["full_tcp_scan"]))
    m.start()

    print(f"{bcolors.HEADER}[*]{bcolors.ENC} Running Quick TCP nmap scans for: {ip_address}")
    results = subprocess.getoutput(custom_scans["quick_tcp_scan"])
    print(f"bcolors.OKGREEN[*]{bcolors.ENDC} Finished with QUICK-TCP-scans for {ip_address}. Starting secondary scans")
    # TCPSCAN = f"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
    #TCPSCAN = f"nmap -sV -Pn -O --top-ports 100 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"

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
                multProc(run_scan_port, "smtp_scan", custom_scans["smtp_scan"], port)

        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "ftp_scan", custom_scans["ftp_scan"], port)

        elif "microsoft-ds" in serv or serv == "netbios-ssn":
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "smb_scan", custom_scans["smb_scan"], port)
                multProc(run_scan_port, "rpc_scan", custom_scans["rpc_scan"], port)
                multProc(run_scan_port, "samr_scan", custom_scans["samr_scan"], port)

        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "mssql_scan", custom_scans["mssql_scan"], port)

        elif "rpcbind" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "nfs_scan", custom_scans["nfs_scan"], port)

        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "ssh_scan", custom_scans["ssh_scan"], port)

        elif "ldap" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "ldap_scan", custom_scans["ldap_scan"], port)

        elif "kerberos-sec" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(run_scan_port, "kerb_scan", custom_scans["kerb_scan"], port)
    return

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

if __name__ == '__main__':
    #multiprocessing.log_to_stderr(logging.DEBUG)

    targets = args.targets.split(" ")

    for scanip in targets:
        scanip = scanip.rstrip()

        # if we don't have a directory for it already, set one up
        if not scanip in subprocess.getoutput(f"ls {dirs}"):
            setup_target_directory(dirs, scanip, myip)

        custom_scans = set_scan_target_and_output(scans)

        p = multiprocessing.Process(target=portScan, args=(scanip,unicorn,resultQueue,custom_scans))
        time.sleep(1)  # Just a nice wait for unicornscan
        p.start()
