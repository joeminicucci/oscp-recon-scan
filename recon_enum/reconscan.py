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
import time

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
def multProc(targetin, ip, port, serviceBanner, termMode):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(ip,port, serviceBanner, termMode))
    jobs.append(p)
    p.start()
    return

def connect_to_port(ip, port, service):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    banner = s.recv(1024)

    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip, "ftp-connect", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip, "smtp-connect", total_communication)
    elif service == "ssh":
        total_communication = banner
        write_to_file(ip, "ssh-connect", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner +  user +  password
        write_to_file(ip, "pop3-connect", total_communication)
    s.close()


def write_to_file(ip, enum_type, data):

    file_path_linux = '../reports/%s/mapping-linux.md' % (ip)
    file_path_windows = '../reports/%s/mapping-windows.md' % (ip)
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

def dirb(ip, port, url_start, wordlist):
    print bcolors.OKBLUE + "{DIRB}"+ bcolors.ENDC
    DIRBSCAN = "dirb %s://%s:%s %s -o \"../reports/%s/dirb.%s-%s.txt\" -r" % (url_start, ip, port, wordlist, ip, url_start, ip)
    print bcolors.OKBLUE + DIRBSCAN + bcolors.ENDC
    print bcolors.OKBLUE + "{DIRB}"+ bcolors.ENDC
    return DIRBSCAN

def nikto(ip, port, url_start):
    print bcolors.OKBLUE + "{NIKTO}"+ bcolors.ENDC
    NIKTOSCAN = "nikto -h %s://%s:%s -o \"../reports/%s/nikto.%s-%s.txt\"" % (url_start, ip, port, ip, url_start, ip)
    if url_start == 'https':
        NIKTOSCAN+=" -ssl"
    print bcolors.OKBLUE + NIKTOSCAN + bcolors.ENDC
    print bcolors.OKBLUE + "{NIKTO}"+ bcolors.ENDC
    return NIKTOSCAN

def curl(ip, port, url_start):
    print bcolors.OKBLUE + "{CURL}"+ bcolors.ENDC
    CURLSCAN = "curl -I -k %s://%s:%s -m 60 -o \"../reports/%s/curl.%s-%s.txt\"" % (url_start,ip,port,ip, url_start, ip)
    print bcolors.OKBLUE + CURLSCAN + bcolors.ENDC
    print bcolors.OKBLUE + "{CURL}"+ bcolors.ENDC
    return CURLSCAN

def httpEnum(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected http on " + ip + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip + ":" + port + bcolors.ENDC

    if termMode:
        dirbproc=multiprocessing.Process(target=openGnomeTerm, args=(ip + " dirb", dirb(ip, port, "http", findWordlists(serviceBanner)), True))
        dirbproc.start()

        nikto_process=multiprocessing.Process(target=openGnomeTerm, args=(ip + " nikto", nikto(ip,port,"http"), True))
        nikto_process.start()

        curl_process=multiprocessing.Process(target=openGnomeTerm, args=(ip + " curl", curl(ip,port,"http"), True))
        curl_process.start()

    else:
        results_dirb = subprocess.check_output(dirb(ip, port, "http", findWordlists(serviceBanner)), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip + bcolors.ENDC
        print results_dirb
        write_to_file(ip, "dirb", results_dirb)

        results_nikto = subprocess.check_output(nikto(ip,port,"http"), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip + bcolors.ENDC
        print results_nikto
        write_to_file(ip, "nikto", results_nikto)

        results_curl = subprocess.check_output(curl(ip,port,"http"), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with CURL scan for " + ip + bcolors.ENDC
        print results_curl
        write_to_file(ip, "curl", results_curl)

    HTTPSCAN = "nmap -sV -Pn -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip, ip, ip)
    print bcolors.HEADER + HTTPSCAN + bcolors.ENDC
    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip + bcolors.ENDC
    print http_results

    return

def httpsEnum(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected https on " + ip + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip + ":" + port + bcolors.ENDC

    if termMode:
        dirbproc=multiprocessing.Process(target=openGnomeTerm, args=(ip + " dirb_https", dirb(ip, port, "https", findWordlists(serviceBanner)), True))
        dirbproc.start()

        nikto_process=multiprocessing.Process(target=openGnomeTerm, args=(ip + " nikto_https", nikto(ip,port,"https"), True))
        nikto_process.start()

        curl_process=multiprocessing.Process(target=openGnomeTerm, args=(ip + " curl_https", curl(ip,port,"https"), True))
        curl_process.start()

    else:
        results_dirb = subprocess.check_output(dirb(ip, port, "https", findWordlists(serviceBanner)), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb_https scan for " + ip + bcolors.ENDC
        print results_dirb
        write_to_file(ip, "dirb", results_dirb)

        results_nikto = subprocess.check_output(nikto(ip,port,"https"), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO_https scan for " + ip + bcolors.ENDC
        print results_nikto
        write_to_file(ip, "nikto", results_nikto)

        results_curl = subprocess.check_output(curl(ip,port,"https"), shell=True)
        print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with CURL_https scan for " + ip + bcolors.ENDC
        print results_curl
        write_to_file(ip, "curl_https", results_curl)


    SSLSCAN = "sslscan %s:%s >> ../reports/%s/ssl_scan_%s" % (ip, port, ip, ip)
    print bcolors.HEADER + SSLSCAN + bcolors.ENDC
    ssl_results = subprocess.check_output(SSLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip + bcolors.ENDC

    HTTPSCANS = "nmap -sV -Pn  -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN ../reports/%s/%s_http.nmap %s" % (port, ip, ip, ip)
    print bcolors.HEADER + HTTPSCANS + bcolors.ENDC
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip + bcolors.ENDC
    print https_results
    return

targettedWordlists = {
    "iis": "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/IIS.fuzz.txt",
    "apache,tomcat,coyote":
        "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/apache.txt,"\
        "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt",
    "php": "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/PHP.fuzz.txt"
}

bruteSupported = ['ssh','ftp','telnet','vnc','mssql','mysql','postgresql','rsh',
                'imap','nntp','pcanywhere','pop3',
                'rexec','rlogin','smbnt','smtp',
                'svn','vmauthd','snmp']

def findWordlists(serviceBanner):
    wordlists=""
    for wordlistType in targettedWordlists:
        if any(serv in serviceBanner.lower() for serv in wordlistType.split(",")):
            wordlists+=targettedWordlists[wordlistType]+","
    wordlists+= "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/common.txt,"\
                "/media/sf_scripts/recon/scripts/SecLists/Discovery/Web-Content/CGIs.txt"
    return wordlists

def mssqlEnum(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected MS-SQL on " + ip + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip + ":" + port + bcolors.ENDC
    MSSQLSCAN = "nmap -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,mysql-empty-password,mysql-brute,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 --script-args=mssql.instance-port=1433,mssql.username=sa,mssql.password=sa -oN ../reports/%s/mssql_%s.nmap %s" % (port, ip, ip)
    print bcolors.HEADER + MSSQLSCAN + bcolors.ENDC
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip + bcolors.ENDC
    print mssql_results
    return


def smtpEnum(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected smtp on " + ip + ":" + port  + bcolors.ENDC
    connect_to_port(ip, port, "smtp")
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN ../reports/%s/smtp_%s.nmap" % (port, ip, ip, ip)
    print bcolors.HEADER + SMTPSCAN + bcolors.ENDC
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip + bcolors.ENDC
    print smtp_results
    # write_to_file(ip, "smtp", smtp_results)
    return

def smbNmap(ip, port, serviceBanner, termMode):
    print "INFO: Detected SMB on " + ip + ":" + port
    smbNmap = "nmap --script=smb-enum-shares,smb-ls,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-vuln-regsvc-dos %s -oN ../reports/%s/smb_%s.nmap" % (ip, ip, ip)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip + bcolors.ENDC
    print smbNmap_results
    return

def smbEnum(ip, port, serviceBanner, termMode):
    print "INFO: Detected SMB on " + ip + ":" + port
    enum4linux = "enum4linux -a %s > ../reports/%s/enum4linux_%s 2>/dev/null" % (ip, ip, ip)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + ip + bcolors.ENDC
    print enum4linux_results
    return

def ftpEnum(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected ftp on " + ip + ":" + port  + bcolors.ENDC
    connect_to_port(ip, port, "ftp")
    FTPSCAN = "nmap -sV -Pn -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '../reports/%s/ftp_%s.nmap' %s" % (port, ip, ip, ip)
    print bcolors.HEADER + FTPSCAN + bcolors.ENDC
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-Nmap-scan for " + ip + bcolors.ENDC
    print results_ftp
    return

def udpScan(ip):
    print bcolors.HEADER + "INFO: Detected UDP on " + ip + bcolors.ENDC
    UDPSCAN = "nmap -Pn -A -sC -sU -T 3 --top-ports 200 -oN '../reports/%s/udp_%s.nmap' %s"  % (ip, ip, ip)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip + bcolors.ENDC
    print udpscan_results
    UNICORNSCAN = "unicornscan -mU -I %s > ../reports/%s/unicorn_udp_%s.txt" % (ip, ip, ip)
    unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip + bcolors.ENDC

def sshScan(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected SSH on " + ip + ":" + port  + bcolors.ENDC
    connect_to_port(ip, port, "ssh")
    SSHSCAN = "nmap -sV -Pn -p %s --script=ssh-auth-methods,ssh-hostkey,ssh-run,sshv1 -oN '../reports/%s/ssh_%s.nmap' %s" % (port, ip, ip, ip)
    print bcolors.HEADER + SSHSCAN + bcolors.ENDC
    results_ssh = subprocess.check_output(SSHSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SSH-Nmap-scan for " + ip + bcolors.ENDC
    print results_ssh
    return

def pop3Scan(ip, port, serviceBanner, termMode):
    print bcolors.HEADER + "INFO: Detected POP3 on " + ip + ":" + port  + bcolors.ENDC
    connect_to_port(ip, port, "pop3")
    POP3SCAN = "nmap -sV -Pn -p %s --script=pop3-brute,pop3-capabilities,pop3-ntlm-info -oN '../reports/%s/pop3_%s.nmap' %s" % (port, ip, ip, ip)
    print bcolors.HEADER + SSHSCAN + bcolors.ENDC
    results_pop3 = subprocess.check_output(POP3SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with POP3-Nmap-scan for " + ip + bcolors.ENDC
    print results_pop3
    return


def nmapScan(ip, intenseMode):
    ip = ip.strip()
    print bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip + bcolors.ENDC

    TCPSCAN = "nmap -sV -O "
    if intenseMode:
        TCPSCAN += "-p- %s -oN '../reports/%s/%s.nmap.intense' -oX ../reports/%s/%s.nmap.intense.xml"  % (ip, ip, ip, ip, ip)
    else :
        TCPSCAN += "%s -oN '../reports/%s/%s.nmap' -oX ../reports/%s/%s.nmap.xml" % (ip, ip, ip, ip, ip)

    print bcolors.HEADER + TCPSCAN + bcolors.ENDC

    results = subprocess.check_output(TCPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip + bcolors.ENDC
    print results

    p = multiprocessing.Process(target=udpScan, args=(ip,))
    p.start()

    write_to_file(ip, "portscan", results)
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

def openGnomeTerm(title, command, spawnTerm):
    gnomeTermCmd = 'gnome-terminal '
    if (spawnTerm):
        #until xdotool problems are figured out for separate windows, going with tab approach
        gnomeTermCmd += '--tab '
        #https://serverfault.com/a/586272
        #gnomeTermCmd +=  '-t \"%s\" -x bash -c "bash --init-file <(echo \'\')"' % title
        gnomeTermCmd +=  '-t \"%s\" -x bash -c "bash --init-file <(echo \'%s\')"' % (title,command)

        print gnomeTermCmd
        gnomeTermProc = subprocess.Popen(gnomeTermCmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         executable='/bin/bash').communicate()

        #all of this logic below works via xdotool, can be re-purposed for tabs https://stackoverflow.com/questions/1188959/open-a-new-tab-in-gnome-terminal-using-command-line
        # #wait for thread
        # # gnomeTermProc.communicate()
        # # windowId = subprocess.check_output("cat /media/sf_scripts/recon/scripts/joe/oscp/reports/%s/windows" % ip, shell=True)
        # XDOSEARCH = 'xdotool search --name \"%s\"' % title
        # print XDOSEARCH
        # # windowId = subprocess.check_output(XDOSEARCH, shell=True, executable='/bin/bash')
        # windowFind = subprocess.Popen(XDOSEARCH, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        #                  executable='/bin/bash')
        # windowId, err = windowFind.communicate()
        # print "window id:" + windowId
        # windowId = windowId.rstrip()
        # # subprocess.check_output("xdotool windowfocus %s"%windowId)
        # subprocess.Popen("xdotool windowfocus %s"%windowId, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        #                  executable='/bin/bash').communicate()

        # print "focus: " + "xdotool windowfocus %s"%windowId

        # # typeCmd="xdotool type --window %s \"%s\""% (windowId, command)
        # typeCmd="xdotool type --window %s \"%s\"" % (windowId, command)
        # print "Type " + typeCmd
        # subprocess.Popen(typeCmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        #                                  executable='/bin/bash').communicate()

        # RET = "xdotool key --window %s Return"% windowId
        # subprocess.check_output(RET, shell=True)

        # # subprocess.check_output("xdotool key %s"% command)
        # #TODO move below to openGnomeTab
    else:
        #spawnterm == false assumes terminalPid is != None, ie hasnt been fired before

        gnomeTermCmd += '--tab '
    # gnomeTermCmd +=  '-t \"%s\" -x bash -c "%s; bash -i;"' % (title, command)
    #print bcolors.OKBLUE + "{SHELL}\n" + gnomeTermCmd + "\n" + "{SHELL}" + bcolors.ENDC
    # gnomeTermProc = subprocess.Popen(gnomeTermCmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, executable='/bin/bash')
    return gnomeTermProc

def openGnomeTab(title, command, windowId):
    return

def bruteForce(ip,term):
    try:


        if term:
            gnomeWindowId = openGnomeTerm(ip + " bRut3 foRc3", bruteSprayCmd(ip), True)
            time.sleep(5)
    except:
        sys.stderr.write("Brute forcing failed, try to run it manually.")

def serviceEnumeration(ip, serviceDict, options):
    if options.brute:
        #multProc(bruteForce, ip, port, serviceBanner)
        proc=multiprocessing.Process(target=bruteForce, args=(ip, options.term)).start()
        #proc.start()

    # go through the service dictionary to call additional targeted enumeration functions
    for serviceBanner in serviceDict:
        ports = serviceDict[serviceBanner]
        # if re.search(r"http[^s]", serv):
        if "http" in serviceBanner and "https" not in serviceBanner and "ssl" not in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip, port, serviceBanner, options.term)
        # elif re.search(r"https|ssl", serv):
        elif "https" in serviceBanner or "ssl" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip, port, serviceBanner, options.term)
        elif "smtp" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip, port, serviceBanner, options.term)
        elif "ftp" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip, port, serviceBanner, options.term)
        elif ("microsoft-ds" in serviceBanner) or ("netbios-ssn" == serviceBanner):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip, port, serviceBanner, options.term)
                multProc(smbNmap, ip, port, serviceBanner, options.term)
        elif "ms-sql" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip, port, serviceBanner, options.term)
        elif "ssh" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip, port, serviceBanner, options.term)
        elif "snmp" in serviceBanner:
            for port in ports:
                port = port.split("/")[0]
                multProc(snmpEnum, ip, port, serviceBanner, options.term)

    return

def bruteSprayCmd(ip):
    #brutespray -f ../reports/%s/%s.nmap.xml -o ../reports/%s/%s.brute -t 5 -T 2
    print bcolors.OKBLUE + "{BRUTE}"+ bcolors.ENDC
    bruteCmd= "brutespray -f ../reports/%s/%s.nmap.xml -o ../reports/%s/%s.brute -t 5 -T 2" % (ip, ip, ip, ip)
    print bruteCmd
    print bcolors.OKBLUE + "{BRUTE}"+ bcolors.ENDC
    return bruteCmd

def enumerateHost(ip, options):
    serviceDict = nmapScan(ip, options.intense)
    if not options.nmapOnly:
        serviceEnumeration(ip, serviceDict, options)
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

def buildReportDirectory(ip):
    print bcolors.HEADER + "INFO: No folder was found for " + ip + ". Setting up folder." + bcolors.ENDC
    subprocess.check_output("mkdir ../reports/" + ip, shell=True)
    subprocess.check_output("mkdir ../reports/" + ip + "/exploits", shell=True)
    subprocess.check_output("mkdir ../reports/" + ip + "/privesc", shell=True)
    subprocess.check_output("mkdir ../reports/" + ip + "/xml", shell=True)
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
    parser.add_argument('--nmap', '-n', action='store_true',
                        help='Run nmap only.', dest='nmapOnly')
    parser.add_argument('--brute', '-b', action='store_true',
                        help='Run brute force mode, all services found which are brute-forceable will be run against brutespray', dest='brute')
    parser.add_argument('--gnome', '-g', action='store_true',
                        help='Attempt to leverage Gnome Terminal to spawn new windows and auto-type enumeration tools.', dest='term')
    options = parser.parse_args()

    reportDirectory = os.listdir("../reports/")
    for ip in options.targets:
        if not ip in reportDirectory:
            buildReportDirectory(ip)

        #openGnomeTerm("test", 'echo hi', True)
        p = multiprocessing.Process(target=enumerateHost, args=(ip,options))
        p.start()

