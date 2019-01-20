#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import re
import argparse

# Todo:
#Replace Curl with HTTP responses which check for body programmatically
#Intense nmap discovery w/vulscan nse
#wordlist auto discovery
# Add mysql nmap-script
#brute forcers / brutespray
# Change replace to sed:
# sed 's|literal_pattern|replacement_string|g'

start = time.time()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, ip, port, serviceBanner):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(ip,port, serviceBanner))
    jobs.append(p)
    p.start()
    return

def connect_to_port(ip_address, port, service):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)

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
        total_communication = banner +  user +  password
        write_to_file(ip_address, "pop3-connect", total_communication)
    s.close()




def write_to_file(ip_address, enum_type, data):

    file_path_linux = '../reports/%s/mapping-linux.md' % (ip_address)
    file_path_windows = '../reports/%s/mapping-windows.md' % (ip_address)
    paths = [file_path_linux, file_path_windows]
    print bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n " + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC

    for path in paths:
        if enum_type == "portscan":
            subprocess.check_output("replace INSERTTCPSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "dirb":
            subprocess.check_output("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "nikto":
            subprocess.check_output("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "ftp-connect":
            subprocess.check_output("replace INSERTFTPTEST \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "smtp-connect":
            subprocess.check_output("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "ssh-connect":
            subprocess.check_output("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "pop3-connect":
            subprocess.check_output("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "curl":
            subprocess.check_output("replace INSERTCURLHEADER \"" + data + "\"  -- " + path, shell=True)
    return



# def dirb(ip_address, port, url_start, wordlist="/usr/share/wordlists/dirb/big.txt,/usr/share/wordlists/dirb/vulns/cgis.txt"):
#     print bcolors.HEADER + "INFO: Starting dirb scan for " + ip_address + bcolors.ENDC
#     DIRBSCAN = "dirb %s://%s:%s %s -o \"../reports/%s/dirb.%s-%s.txt\" -r" % (url_start, ip_address, port, wordlist, ip_address, url_start, ip_address)
#     print bcolors.HEADER + DIRBSCAN + bcolors.ENDC
#     results_dirb = subprocess.check_output(DIRBSCAN, shell=True)
#     print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip_address + bcolors.ENDC
#     print results_dirb
#     write_to_file(ip_address, "dirb", results_dirb)
#     return

def dirb(ip_address, port, url_start, wordlist):
    #want to run dirb manually in separate terminals
    print bcolors.OKBLUE + "{DIRB}"+ bcolors.ENDC
    DIRBSCAN = "dirb %s://%s:%s %s -o \"../reports/%s/dirb.%s-%s.txt\" -r" % (url_start, ip_address, port, wordlist, ip_address, url_start, ip_address)
    print bcolors.OKBLUE + DIRBSCAN + bcolors.ENDC
    return

# def nikto(ip_address, port, url_start):
#     print bcolors.HEADER + "INFO: Starting nikto scan for " + ip_address + bcolors.ENDC
#     NIKTOSCAN = "nikto -h %s://%s:%s -o \"../reports/%s/nikto.%s-%s.txt\"" % (url_start, ip_address, port, ip_address, url_start, ip_address)
#     print bcolors.HEADER + NIKTOSCAN + bcolors.ENDC
#     results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
#     print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip_address + bcolors.ENDC
#     print results_nikto
#     write_to_file(ip_address, "nikto", results_nikto)
#     return

def nikto(ip_address, port, url_start):
    print bcolors.OKBLUE + "{NIKTO}"+ bcolors.ENDC
    NIKTOSCAN = "nikto -h %s://%s:%s -o \"../reports/%s/nikto.%s-%s.txt\"" % (url_start, ip_address, port, ip_address, url_start, ip_address)
    print bcolors.OKBLUE + NIKTOSCAN + bcolors.ENDC
    return

def httpEnum(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC


    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"http", findWordlists(serviceBanner)))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"http"))
    nikto_process.start()

    CURLSCAN = "curl -I http://%s:%s -m 60" % (ip_address,port)
    print bcolors.HEADER + CURLSCAN + bcolors.ENDC
    curl_results = subprocess.check_output(CURLSCAN, shell=True)
    write_to_file(ip_address, "curl", curl_results)
    HTTPSCAN = "nmap -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCAN + bcolors.ENDC

    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip_address + bcolors.ENDC
    print http_results

    return

def httpsEnum(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    findWordlists(serviceBanner)
    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"https"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"https"))
    nikto_process.start()

    SSLSCAN = "sslscan %s:%s >> ../reports/%s/ssl_scan_%s" % (ip_address, port, ip_address, ip_address)
    print bcolors.HEADER + SSLSCAN + bcolors.ENDC
    ssl_results = subprocess.check_output(SSLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip_address + bcolors.ENDC

    HTTPSCANS = "nmap -sV -Pn  -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCANS + bcolors.ENDC
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip_address + bcolors.ENDC
    print https_results
    return

targettedWordlists = {
    "iis": "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/IIS.fuzz.txt",
    "apache,tomcat,coyote":
        "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/apache.txt,"\
        "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt",
    "php": "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/PHP.fuzz.txt"
}
def findWordlists(serviceBanner):
    wordlists=""
    for wordlistType in targettedWordlists:
        if any(serv in serviceBanner.lower() for serv in wordlistType.split(",")):
            wordlists+=targettedWordlists[wordlistType]+","
    wordlists+= "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/common.txt,"\
                "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/CGIs.txt"
    return wordlists

def mssqlEnum(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port + bcolors.ENDC
    MSSQLSCAN = "nmap -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,mysql-empty-password,mysql-brute,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 --script-args=mssql.instance-port=1433,mssql.username=sa,mssql.password=sa -oN ../reports/%s/mssql_%s.nmap %s" % (port, ip_address, ip_address)
    print bcolors.HEADER + MSSQLSCAN + bcolors.ENDC
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip_address + bcolors.ENDC
    print mssql_results
    return


def smtpEnum(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected smtp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN ../reports/%s/smtp_%s.nmap" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SMTPSCAN + bcolors.ENDC
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip_address + bcolors.ENDC
    print smtp_results
    # write_to_file(ip_address, "smtp", smtp_results)
    return

def smbNmap(ip_address, port, serviceBanner):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    smbNmap = "nmap --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-regsvc-dos %s -oN ../reports/%s/smb_%s.nmap" % (ip_address, ip_address, ip_address)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip_address + bcolors.ENDC
    print smbNmap_results
    return

def smbEnum(ip_address, port, serviceBanner):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    enum4linux = "enum4linux -a %s > ../reports/%s/enum4linux_%s 2>/dev/null" % (ip_address, ip_address, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + ip_address + bcolors.ENDC
    print enum4linux_results
    return

def ftpEnum(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected ftp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = "nmap -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '../reports/%s/ftp_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + FTPSCAN + bcolors.ENDC
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ftp
    return

def udpScan(ip_address):
    print bcolors.HEADER + "INFO: Detected UDP on " + ip_address + bcolors.ENDC
    UDPSCAN = "nmap -Pn -A -sC -sU -T 3 --top-ports 200 -oN '../reports/%s/udp_%s.nmap' %s"  % (ip_address, ip_address, ip_address)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip_address + bcolors.ENDC
    print udpscan_results
    UNICORNSCAN = "unicornscan -mU -I %s > ../reports/%s/unicorn_udp_%s.txt" % (ip_address, ip_address, ip_address)
    unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip_address + bcolors.ENDC

def sshScan(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected SSH on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ssh")
    SSHSCAN = "nmap -sV -Pn -p %s --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1 -oN '../reports/%s/ssh_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SSHSCAN + bcolors.ENDC
    results_ssh = subprocess.check_output(SSHSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SSH-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ssh
    return

def pop3Scan(ip_address, port, serviceBanner):
    print bcolors.HEADER + "INFO: Detected POP3 on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "pop3")
    POP3SCAN = "nmap -sV -Pn -p %s --script=pop3-brute,pop3-capabilities,pop3-ntlm-info -oN '../reports/%s/pop3_%s.nmap' %s" % (port, ip_address, ip_address, ip_address)
    print bcolors.HEADER + SSHSCAN + bcolors.ENDC
    results_pop3 = subprocess.check_output(POP3SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with POP3-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_pop3
    return


def nmapScan(ip_address, intenseMode):
    ip_address = ip_address.strip()
    print bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC

    TCPSCAN = "nmap -sV -O %s -oN '../reports/%s/%s.nmap'"  % (ip_address, ip_address, ip_address)
    print bcolors.HEADER + TCPSCAN + bcolors.ENDC
    results = subprocess.check_output(TCPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC
    print results

    p = multiprocessing.Process(target=udpScan, args=(ip,))
    p.start()

    write_to_file(ip_address, "portscan", results)
    lines = results.split("\n")
    serviceDict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # print line
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit= line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto
            # print port
            if service in serviceDict:
                ports = serviceDict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            # print ports
            serviceDict[service] = ports # add service to the dictionary along with the associated port(2)

    return serviceDict

def serviceEnumeration(ip, serviceDict, bruteForceMode):
       # go through the service dictionary to call additional targeted enumeration functions
    for serv in serviceDict:
        ports = serviceDict[serv]
        # if re.search(r"http[^s]", serv):
        if "http" in serv and "https" not in serv and "ssl" not in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip, port, serv)
        # elif re.search(r"https|ssl", serv):
        elif "https" in serv or "ssl" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip, port, serv)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip, port, serv)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip, port, serv)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip, port, serv)
                multProc(smbNmap, ip, port, serv)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip, port, serv)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip, port, serv)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip, port, serv)

    return

def enumerateHost(ip, intense, brute):
    serviceDict = nmapScan(ip, intense)
    serviceEnumeration(ip, serviceDict, brute)
    return

print bcolors.HEADER
print "------------------------------------------------------------"
print "!!!!                      RECON SCAN                   !!!!!"
print "!!!!            A multi-process service scanner        !!!!!"
print "!!!!        dirb, nikto, ftp, ssh, mssql, pop3, tcp    !!!!!"
print "!!!!                    udp, smtp, smb                 !!!!!"
print "------------------------------------------------------------"

fiddyCal="""
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWWMMMMMWWWWWMMWXKXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWWW0k0kooooolcc::cc;;o0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWMMNKk,.'............  ,0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMNl...............;ll;cKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWMMMM
MMMMMMMMMMMMMMMMMMWkol;';'.......,kNWMWNNNNWMWMMMMMWNXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
Kxxdodddddddddddddddool:c;.'.'...,looooo:;:clclllll:,',cdOOOOOOOOOOOOkkkkkkkkkkkkkxdoooodK
x...................... ................................,:ccccccccccccccccccclllllc:;;:;l0
0,.cxxxxxxc;oxxxxkxl'...............':okkdclxOkkOOOOOOOOXWWMMMMWWMMMMMMMMMMMMMMMMMMWWWWWWM
O'.lOkxddoo0MMWMMWMNl..,:c,.........,codoolkNWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
Kl;:oodxOOXMMMMMMNOc..:xkOx;.......'lO0000KNMMWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MWNWMMMMMMMMMMMMMO,.'oXMWMWo...''',c0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMNKO0XMMMMW0dxO0KXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
"""
print(fiddyCal)

print bcolors.ENDC

headshot="""
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@#;;;;#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@;  ``    ` `'@#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@:          ` `  ,@@@@@@@@@@@@@@@@@@@@@@@@'@@@@@@
@@@@@@@ `    `            '@@@@@@@@@@@@@@@@@@@@@'`.@#`@@
@@@@@#   ``:`@  ..`     `  .@@@@@@@@@@@@@@@@@@@@  ##``,@
@@@@@  ` `;@@@@@@@         `.@@@@@@@@@@@@@@@@@@@' #  `@@
@@@@ ` ,,.#@@@@@@@`       ````::::;;;;;;;;;'+@@@@@` `#@@
@@@,  `;@@@@@@@@@@@.``                        .@@@@,@@@@
@@@     @@@@@@@@@@@@@`                       ` ` +@# ```
@@'    ;@@@@@@@@@@@@@`                           +@#`   
@@`  `@@@@@@@@@@@@@@ `                         '@@@@###'
@@   `` .@@@@@@@@@@@``            ,,.........;@@@@@ +#@@
@@      `@@@@@@@@@@@@`            @@@@@@@@@@@@@@@@#``'@#
@#      ` @@@@@@@@'`             `+@@@@@@@@@@@@@'`.#``'@
@#`     ``@@@@@@@@+               `@@@@@@@@@@@@@@  @+``#
@#        #@`@@@                   @@@@@@@@@@@@@@' #@+`@
@#        ` ` @`  `   `            @@@@@@@@@@@@@@@@@@@@@
@@`           `  `   #@@# ``    ` `@@@@@@@@@@@@@@@@@@@@@
@@                `;@@@@@@.`   ` . @@@@@@@@@@@@@@@@@@@@@
@@                 @@@@@@@@ `` .@@,@@@@@@@@@@@@@@@@@@@@@
@@.                @@@@@@@+`   @@#@@@@@@@@@@@@@@@@@@@@@@
@@'`                @@@@@#   ` @@:@@@@@@@@@@@@@@@@@@@@@@
@@@                `  .. `     .@:@@@@@@@@@@@@@@@@@@@@@@
@@@                 ``  `      `` @@@@@@@@@@@@@@@@@@@@@@
@@@`                             `#@@@@@@@@@@@@@@@@@@@@@
@@@;                             `;@@@@@@@@@@@@@@@@@@@@@
@@@@                              .@@@@@@@@@@@@@@@@@@@@@
@@@@                              ,@@@@@@@@@@@@@@@@@@@@@
@@@@                              '@@@@@@@@@@@@@@@@@@@@@
@@@@`                            `@@@@@@@@@@@@@@@@@@@@@@
@@@@.                            `@@@@@@@@@@@@@@@@@@@@@@
@@@@`                  `` :'';:  @@@@@@@@@@@@@@@@@@@@@@@
@@@@                    +@@@@@@@`@@@@@@@@@@@@@@@@@@@@@@@
@@@@                   ,@@@@@@@@;@@@@@@@@@@@@@@@@@@@@@@@
@@@#`                   ,@@@@@@+@@@@@@@@@@@@@@@@@@@@@@@@
@@@;                      '@@@+ @@@@@@@@@@@@@@@@@@@@@@@@
@@@`                      `` ``.@@@@@@@@@@@@@@@@@@@@@@@@
@@@                           `#@@@@@@@@@@@@@@@@@@@@@@@@
@@@ `                        ` @@@@@@@@@@@@@@@@@@@@@@@@@
@@@+`                         #@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@+`                    `` .@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@+`                   ``,@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@#+                    ,#@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@# `                 ;@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@                  `@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@`                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@:`               @@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@  `      `  ` #@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@+ ``     ` ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@:`   `;@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""

def buildReportDirectory(ip):
    print bcolors.HEADER + "INFO: No folder was found for " + ip + ". Setting up folder." + bcolors.ENDC
    subprocess.check_output("mkdir ../reports/" + ip, shell=True)
    subprocess.check_output("mkdir ../reports/" + ip + "/exploits", shell=True)
    subprocess.check_output("mkdir ../reports/" + ip + "/privesc", shell=True)
    print bcolors.OKGREEN + "INFO: Folder created here: " + "../reports/" + ip + bcolors.ENDC
    subprocess.check_output("cp ../templates/windows-template.md ../reports/" + ip + "/mapping-windows.md", shell=True)
    subprocess.check_output("cp ../templates/linux-template.md ../reports/" + ip + "/mapping-linux.md", shell=True)
    print bcolors.OKGREEN + "INFO: Added pentesting templates: " + "../reports/" + ip + bcolors.ENDC
    subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + ip + "/g' ../reports/" + ip + "/mapping-windows.md",
                            shell=True)
    subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + ip + "/g' ../reports/" + ip + "/mapping-linux.md",
                            shell=True)


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Intrusive reconnaissance engagement tool.')
    parser.add_argument('--target', '-t', nargs="+", type=str, required=True,
                        help='The IP(s) you want to assault, space delimited', metavar="IP Target(s)", dest='targets')
    parser.add_argument('--intense', '-i', action='store_true',
                        help='Run nmap intensively against every port.', dest='intense')
    parser.add_argument('--brute', '-b', action='store_true',
                        help='Run brute force mode, all services found which are brute-forceable will be run against brutespray', dest='brute')
    options = parser.parse_args()
    intense = options.intense
    brute = options.brute

    reportDirectory = os.listdir("../reports/")
    for ip in options.targets:
        if not ip in reportDirectory:
            buildReportDirectory(ip)

        p = multiprocessing.Process(target=enumerateHost, args=(ip,intense,brute))
        p.start()

    # print bcolors.HEADER
    # print (headshot)
    # print bcolors.ENDC
