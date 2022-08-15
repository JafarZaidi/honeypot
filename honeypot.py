from tracemalloc import start
from typing import Any
import paramiko
from pathlib import Path 
import socket
import traceback
import sys
import threading
import _thread
HOST_KEY = paramiko.RSAKey(filename='id_rsa')
log = []
listOfFiles = []
strangeIssue = []
LOGFILE_LOCK = threading.Lock()

class SSHServerHandler (paramiko.ServerInterface):
    
    def __init__(self):
        self.event = threading.Event()
        
    def check_channel_request(self, kind: str, chanid: int) -> int:
        return 0
    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True
    def check_channel_pty_request(self, channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes):
        return True
    def check_channel_exec_request(self, channel, command: bytes):
        return True
    
    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()
        foundUser = 0
        numAttempts = 0
        try:
            
            print("New login: " + username + ":" + password)
            for user in log:
                if user[0] == username:
                    user[1] = user[1]+ 1
                    foundUser = 1
                    numAttempts = user[1]
                    
                    print(log)
            if foundUser == 0:
                log.append([username, 1])
                print(log)
        finally:
            LOGFILE_LOCK.release()
        if(numAttempts>5):
            strangeIssue.append(username)
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

def handle_cmd(command, channel, client_ip):
    
    command = str(command)
    if command.startswith("echo "):
        if command.find('"') == -1 or command.find(">") == -1 or command.find('"', command.index('"')+1) == -1:
            channel.send("incorrect echo format\r\n")
            return
        content = command[command.index('"'): command.index('"', command.index('"')+1)+1].strip()
        
        file = command[command.index(">")+2:].strip()
        
        if not file.endswith(".txt"):
            channel.send("Unknown file extension\r\n")
            return
        
        listOfFiles.append((file, content))
        
    if command.startswith("ls"):
        allFiles = ""
        print(listOfFiles)
        for fileTuple in listOfFiles:
            if allFiles == "":
                allFiles = fileTuple[0]
            else:
                allFiles = allFiles + " " + fileTuple[0]
        if allFiles == "":
            return
        else:
            channel.send(allFiles+ "\r\n")
            return
        
    if command.startswith("cat "):
        file = command[4:].strip()
        if not file.endswith(".txt"):
            channel.send("Unknown file extension\r\n")
            return
        for fileTuple in listOfFiles:
            if fileTuple[0] == file:
                content = fileTuple[1]
                content = content[1:-1]
                channel.send(content + "\r\n")
                return
        channel.send("File " + file + " not found\r\n")
        return
    
    if command.startswith("cp "):
        if command.find(".txt") == -1:
            channel.send("Unknown file extension\r\n")
            return
        if command.find(".txt", command.index(".txt")+4) ==-1:
            channel.send("Unknown file extension\r\n")
            return
        
        sourceFile = command[3:command.index(".txt")+4].strip()
        destFile= command[command.index(".txt")+4:].strip()
        
        for fileTuple in listOfFiles:
            print(fileTuple[0])
            if fileTuple[0] == sourceFile:
                listOfFiles.append((destFile, fileTuple[1]))
                return
        channel.send("File " + sourceFile + " not found\r\n")
        return
        
    
def handleConnection(client, addr):
    
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    server_handler = SSHServerHandler()
    transport.start_server(server=server_handler)
    channel = transport.accept(10)
    print(channel)

    if channel is None:
        return
    
    channel.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
    run = True
    while run:
        thisName = len(strangeIssue) - 1
        print(strangeIssue[thisName])
        nameToSend = strangeIssue[0] + "@honeypot:/$ "
        channel.send(nameToSend)
        command = ""
        while not command.endswith("\r"):
            transport = channel.recv(1024)
            channel.send(transport)
            command += transport.decode("utf-8")
        channel.send("\r\n")
        command = command.rstrip()
        if command == "exit":
            run = False
            
        else:
            client_ip = addr[0]
            handle_cmd(command, channel, client_ip)
        
def main():
    argnum = len(sys.argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if(argnum >= 3):
        port_to_bind = sys.argv[2]
        print(port_to_bind)
        sock.bind(('127.0.0.1', int(port_to_bind)))
    else:
        sock.bind(('127.0.0.1', 22))
    paramiko.util.log_to_file ('paramiko.log') 
    sock.listen(100)
    while True:
        try:
            print('Waiting on Connections...')
            client_sock, client_addr = sock.accept()
            _thread.start_new_thread(handleConnection,(client_sock,client_addr))
        except:
            print('Exception')
        


main()
