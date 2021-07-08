#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Github: sonicCrypt0r (https://github.com/sonicCrypt0r)
# Description: This Script Is For Saving Cisco Running Configs And Show Commands

VERSION = 0.1

# Place where folders will generate
WORKING_DIR = ''
SUB_DIR = 'Sites/'

# Global Imports
from sys import stdout
sprint = stdout.write


def main():
# Main Logic of the program
    import time
    import os
    import sys

    # Start timer
    startTime = time.time()

    # Window title If Windows
    if os.name == 'nt':
        os.system('title ' + 'Cisco Analyzer V' + str(VERSION))

    # Fancy banner for #If The device seems up based on ping
    banner()

    # Print version information 
    sprint(pStatus("GOOD") + 'Cisco Analyzer V' + str(VERSION))

    # Check for updates
    checkUpdate()

    # Get device IP, username, password, storage folder from the user
    (deviceIP, cidr, folderName, username, password) = getInput()

    hostList = networkScan(deviceIP, cidr)

    i = 0
    while i < len(hostList):
        # If The device seems up based on ping
        sprint(pStatus('GOOD') + 'Attempting To Connect To Device... ')
        remote_conn = SSHDevice(hostList[i], username, password)

        hostname = pullHostname(remote_conn, hostList[i]) # Pull hostname from cisco device
        sprint(pStatus('GOOD') + 'Hostname: ' + hostname)

        config = pullConfig(remote_conn, hostList[i]) # Pull running config from Cisco device
        saveToFile('config', config, hostname, folderName)

        info = pullInfo(remote_conn, hostList[i]) # Issue show commands pull output from Cisco device
        saveToFile('info', info, hostname, folderName)

        i = i + 1

    Exectime = (time.time() - startTime) / 60 # End timer calculate elapsed time in minutes
    sprint(pStatus('GOOD') + 'Completed In: ('
           + str(round(Exectime, 2)) + ' Minutes)')


def networkScan(addr, cidr):
    import networkscan
        
    addr = [int(x) for x in addr.split(".")]
    cidr = int(cidr)
    mask = [( ((1<<32)-1) << (32-cidr) >> i ) & 255 for i in reversed(range(0, 32, 8))]
        
    netw = [addr[i] & mask[i] for i in range(4)]
    
    IP = "{0}".format('.'.join(map(str, netw)))

    my_network = (IP + "/" + str(cidr))

    # Create the object
    my_scan = networkscan.Networkscan(my_network)

    # Run the scan of hosts using pings
    my_scan.run()

    return my_scan.list_of_hosts_found


def checkUpdate():
# This function checks for updates from Github
    import requests
    import os
    import sys
    # Disable no SSL verification console log
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    curScriptName = sys.argv[0]
    newScriptName = sys.argv[0].split(".py")[0] + "_new.py"

    # Remove 'Cisco-Device-Analyzer_new.py' and 'updater.bat' which may be from previous updates
    try:
        os.remove(newScriptName)
    except:
        nothing = 'nothing'

    # Download newest version of 'Cisco-Device-Analyzer.py' from Github with the name 'Cisco-Device-Analyzer_new.py'
    url = \
        'https://raw.githubusercontent.com/sonicCrypt0r/Cisco-Device-Analyzer/main/Cisco-Device-Analyzer.py' #Location Where Updated Source Code Will Be
    sprint(pStatus('GOOD') + 'Checking For Updates... ')
    r = requests.get(url, verify=False)
    open(newScriptName, 'wb').write(r.content)

    # Find the version from 'Cisco-Device-Analyzer_new.py'
    phrase = 'VERSION ='
    line_number = 'Phrase not found'
    a_file = open(newScriptName, 'r')
    for (number, line) in enumerate(a_file):
        if phrase in line:
            line_number = number
            newVersion = float(line.split('=')[1].strip())
            sprint(pStatus('GOOD') + 'Newest Version Is: V'
                   + str(newVersion))
            break
    a_file.close()

    if newVersion > VERSION:
        os.remove(curScriptName)
        os.rename(newScriptName, curScriptName)
        if os.name == 'nt':
            os.system("python " + curScriptName)
        else:
            os.system("python3 " + curScriptName)
        sys.exit()
    else:
        os.remove(newScriptName) #remove the downloaded code from Github
    return


def pStatus(status):
    #This function is for fancy output throughout the program

    # Colors used for fancy output
    COLORS = {
        'WARN': '\033[93m',
        'GOOD': '\033[92m',
        'BAD': '\033[91m',
        'INPUT': '\033[96m',
        'ENDC': '\033[0m',
        'UP': '\033[F',
        }

    if status == 'GOOD':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['GOOD'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'BAD':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['BAD'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'WARN':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['WARN'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'INPUT':
        return '\n' + COLORS['ENDC'] + '[' + COLORS['INPUT'] + '+' \
            + COLORS['ENDC'] + '] '
    if status == 'UP':
        return COLORS['UP']


def getInput():
    #This function gets device IP, Folder Name, Username, Password from the user
    import getpass

    #Prompt for device IP
    sprint(pStatus('INPUT') + 'Device IP: ')
    deviceIP = input()
    sprint(pStatus('UP'))

    #Prompt for device IP
    sprint(pStatus('INPUT') + 'CIDR: ')
    cidr = input()
    sprint(pStatus('UP'))

    #Prompt for folder name
    sprint(pStatus('INPUT') + 'Folder Name: ')
    folderName = input()
    sprint(pStatus('UP'))

    #Prompt for username
    sprint(pStatus('INPUT') + 'Username: ')
    username = input()
    sprint(pStatus('UP'))

    #Prompt for password
    sprint(pStatus('INPUT'))
    password = getpass.getpass()
    sprint(pStatus('UP'))

    #Return all the gathered input
    return (deviceIP, cidr, folderName, username, password)


def SSHDevice(deviceIP, username, password):
    #This function SSHs into a device with username, password supplied.
    #This function returns 'remote_conn' which can be used to interact with the SSH session
    import paramiko
    import traceback

    try:
        remote_conn_pre = paramiko.SSHClient()
        remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        remote_conn_pre.connect(
            deviceIP,
            port=22,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            )

        remote_conn = remote_conn_pre.invoke_shell()
        sprint('Done')
        sprint(pStatus('GOOD') + 'Connected to ' + deviceIP)
        return remote_conn
    except:
        sprint(pStatus('BAD')
               + 'Failed SSH Would You Like To See The Error Trace: ')
        showError = input().upper()
        sprint(pStatus('UP'))
        if showError == 'Y' or showError == 'YES':
            traceback.print_exc()
        else:
            main()


def pullHostname(remote_conn, deviceIP):
    import traceback
    import time

    sprint(pStatus('GOOD') + 'Pulling Hostname... ')

    try:
        remote_conn.send('term len 0\n')
        time.sleep(2)
        remote_conn.recv(65535)

        remote_conn.send('show run | inc hostname\n')
        time.sleep(10)
        output = str(remote_conn.recv(65535)).replace('\\r\\n', '\n'
                ).split('\n')[1].replace('hostname ', '')

        remote_conn.send('term len 20\n')
        time.sleep(2)
        remote_conn.recv(65535)
        sprint('Done')

        return output
    except:
        sprint(pStatus('UP') + pStatus('BAD') + 'Pulling Hostname From '
                + deviceIP + ' Failed')

        sprint(pStatus('BAD')
               + 'Would You Like To See The Error Trace: ')
        showError = input().upper()
        sprint(pStatus('UP'))
        if showError == 'Y' or showError == 'YES':
            traceback.print_exc()
        else:
            main()


def pullConfig(remote_conn, deviceIP):
    import traceback
    import time

    sprint(pStatus('GOOD') + 'Downloading Config... ')

    try:
        remote_conn.send('term len 0\n')
        time.sleep(2)
        remote_conn.recv(65535)

        remote_conn.send('show run\n')
        time.sleep(20)
        output = remote_conn.recv(65535)

        remote_conn.send('term len 20\n')
        time.sleep(2)
        remote_conn.recv(65535)

        sprint('Done')

        return output
    except:
        sprint(pStatus('UP') + pStatus('BAD')
               + 'Downloading Config From ' + deviceIP + ' Failed')

        sprint(pStatus('BAD')
               + 'Would You Like To See The Error Trace: ')
        showError = input().upper()
        sprint(pStatus('UP'))
        if showError == 'Y' or showError == 'YES':
            traceback.print_exc()
        else:
            main()


def pullInfo(remote_conn, deviceIP):
    import traceback
    import time

    showCommands = [
        'Show Version',
        'Show Inventory',
        'Show IP Route',
        'Show Vlan',
        'Show Interface Trunk',
        'Show IP Interface Brief',
        ]

    sprint(pStatus('GOOD') + 'Gathering Other Information: ')

    remote_conn.send('term len 0\n')
    time.sleep(2)
    remote_conn.recv(65535)

    i = 0
    output = bytearray()
    while i < len(showCommands):
        sprint(pStatus('GOOD') + 'Executing: ' + showCommands[i]
               + '... ')
        remote_conn.send(showCommands[i] + '\n')
        time.sleep(10)
        output.extend(remote_conn.recv(65535))
        sprint('Done')
        i = i + 1

    remote_conn.send('term len 20\n')
    time.sleep(2)
    remote_conn.recv(65535)
    remote_conn.close()

    return output


def saveToFile(
    type,
    config,
    hostname,
    folderName,
    ):
    import datetime
    import os

    timestr = datetime.datetime.now().strftime('%m_%d_%Y_%H_%M_%S')

    if not os.path.exists(WORKING_DIR + SUB_DIR):
        os.mkdir(WORKING_DIR + SUB_DIR)

    if not os.path.exists(WORKING_DIR + SUB_DIR + folderName + '/'):
        os.mkdir(WORKING_DIR + SUB_DIR + folderName + '/')

    if not os.path.exists(WORKING_DIR + SUB_DIR + folderName + '/' + hostname + "/"):
        os.mkdir(WORKING_DIR + SUB_DIR + folderName + '/' + hostname + "/")

    if type == 'config':
        f = open(WORKING_DIR + SUB_DIR + folderName + '/' + hostname + "/" + hostname
                 + '-Config-' + timestr + '.txt', 'wb')
    else:
        f = open(WORKING_DIR + SUB_DIR + folderName + '/' + hostname + "/" + hostname
                 + '-Info-' + timestr + '.txt', 'wb')
    f.write(config)
    f.close()


def banner():
    print('''
     _______  ___  _______  _______  _______   _______  __    _  _______  ___     __   __  _______  _______  ______   
    |       ||   ||       ||       ||       | |   _   ||  |  | ||   _   ||   |   |  | |  ||       ||       ||    _ |  
    |       ||   ||  _____||       ||   _   | |  |_|  ||   |_| ||  |_|  ||   |   |  |_|  ||____   ||    ___||   | ||  
    |       ||   || |_____ |       ||  | |  | |       ||       ||       ||   |   |       | ____|  ||   |___ |   |_||_ 
    |      _||   ||_____  ||      _||  |_|  | |       ||  _    ||       ||   |___|_     _|| ______||    ___||    __  |
    |     |_ |   | _____| ||     |_ |       | |   _   || | |   ||   _   ||       | |   |  | |_____ |   |___ |   |  | |
    |_______||___||_______||_______||_______| |__| |__||_|  |__||__| |__||_______| |___|  |_______||_______||___|  |_|
                                                                                        By: sonicCrypt0r''')


if __name__ == '__main__':
    main()
