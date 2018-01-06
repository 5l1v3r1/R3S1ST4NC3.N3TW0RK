#!/usr/bin/python
# Still unfinished!
# ToDo: Fix whitelist and secure chat. Shit's now being send in plaintext!

import os, sys, getpass, time, datetime, socket, select, platform, random, string, shutil
from collections import Counter
try:
    from Crypto import Random
    from Crypto.Cipher import AES
except:
    _yn = raw_input('[!] python-crypto not installed, would you like to install it now? (y/n): ')
    try:
        if _yn == 'y':
            os.system('sudo apt-get install python-crypto')
        elif _yn == 'Y': # << This is pure lazyness
            os.system('sudo apt-get install python-crypto')
            delay('[\033[92m+\033[0m] Installation..........................................[\033[1;92mCOMPLETE\033[0m]')
        else:
            delay('[\033[92m!\033[0m] Critical system failure > Shutting down...')
    except Exception as e:
        delay('[\033[92m!\033[0m] Critical system failure > ' + e + '\n \033[95m>>> Shutting down...\033[0m')

os.system('clear')

def delay(s):
    for line in s:
        for l in s:
            sys.stdout.write(l); sys.stdout.flush()
            time.sleep(0.02)
        if 'Shutting down' in s:
            sys.exit()
        elif 'chat.py......' in s:
            return chat()
        elif 'register.py....' in s:
            return register()
        elif 'logon.py....' in s:
            return logon()
        elif 'Launching network....' in s:
            return boot()
        else:
            return user_input()

logo = '''
\033[92m                            ,,,,^^^^^^\___/^^^^^^,,,,\033[0m
\033[92m                   ...,,,;;;                         ;;;,,,...\033[0m
\033[92m   ////////////////             \033[1mR3S1ST4NC3.N3TW0RK\033[0m             \033[92m\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\033[0m
\033[92m   \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\                                            ////////////////\033[0m
\033[92m                   ```~~~;;;,,,...____/----\____...,,,;;;~~~```\033[0m

'''

halp = '''
Help:
    \033[1;95mCommand\033[0m\t\t\t| \033[1;95mDescription\033[0m
    boot\t\t\t| Host chat server on this device
    clear\t\t\t| Clear terminal screen
    logo\t\t\t| Print System logo
    chat.py\t\t\t| Chat application to communicate with other fighters
    register\t\t\t| Register a new user
    login\t\t\t| Login to the given resistance network
    return\t\t\t| Return to main console
    set default\t\t\t| Set a default IP and Port for all services
    del default\t\t\t| Clear default IP and Port
    exit\t\t\t| Terminate the service
'''

def user_input():
    try:
        s = raw_input('#\R\safehouse>')
        if s == 'logo':
            delay(logo)
        elif s == 'boot':
            if os.path.isfile('default.txt'):
                with open('default.txt') as f:
                    split = f.readline(); f.close()
                    split = split.split(':')
                    ip = split[0]; port = split[1]
                    status = 'COMPLETE'
            else:
                status = 'NOT FOUND'; port = 4546
            delay('''
    [\033[92m+\033[0m] Reading config..............................[\033[1;92m%s\033[0m]
    [\033[92m+\033[0m] Binding to port.............................[\033[1;92mCOMPLETE\033[0m]
        [\033[92m!\033[0m] Bound to port %s
    [\033[92m+\033[0m] Launching network...........................[\033[1;92mCOMPLETE\033[0m]

    Resistance Network [Version 0.1.7601]///////////////////////////////\n
    %s
''' % (status, port, logo))
        elif s == 'exit':
            delay('''
    [\033[93m-\033[0m] Stopping all services...........................[\033[1;92mCOMPLETE\033[0m]

\033[95m>> Shutting down...\033[0m
''')
            delay('\nShutting down...\n')
        elif s == 'help':
            delay(halp)
        elif s == '?':
            delay(halp)
        elif s == 'register':
            delay('''
    [\033[92m+\033[0m] Loading register.py...........................[\033[1;91mFAILED\033[0m]
''')
        elif s == 'login':
            delay('''
    [\033[92m+\033[0m] Loading logon.py...........................[\033[1;91mFAILED\033[0m]
''')
        elif s == 'chat.py':
            delay('''
    [\033[92m+\033[0m] Loading chat.py...........................[\033[1;92mCOMPLETE\033[0m]
''')
        elif s == 'return':
            return user_input()
        elif s == 'set default':
            default()
        elif s == 'del default':
            deldefault()
        elif s == 'clear':
            os.system('clear'); return user_input()
        else:
            delay('Unknown command\n')
    except KeyboardInterrupt:
            delay('''
    [\033[93m-\033[0m] Stopping all services...........................[\033[1;92mCOMPLETE\033[0m]

\033[95m>> Shutting down...\033[0m
''')
def register():
    delay('\t[\033[91m!\033[0m] ERROR: Comming Soon!\n')

    # Registration not yet finished! Might even be removed, so don't even bother..
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)

    username = raw_input('Username: ')
    if username.count('', 0) < 4:
        delay('[\0331;91mERROR\033[0m] Username should be at least 4 characters')
    passwd = getpass.getpass('Password: ')
    if passwd.count('', 0) < 7:
        delay('[\0331;91mERROR\033[0m] Password should be at least 7 characters')
    passwd_conf = getpass.getpass('Confirm Password: ')
    if not passwd_conf == passwd:
        delay('[\033[91mERROR\033[0m] Passwords do not match')

    if os.path.isfile('default.txt'):
        with open('default.txt') as f:
            split = f.readline()
            split = split.split(':')
            ip = split[0]; port = int(split[1])
            f.close()
    else:
        ip = raw_input('IP address: ')
        port = raw_input('Port: ')
    try:
        s.connect((ip, port))
        msg = '[\033[92m+\033[0m] Connecting to server...........................[\033[1;92mCOMPLETE\033[0m]\n\t[\0331;[95m!\033[0m] Connected to %s:%i' % (ip, port)
        for l in msg:
            sys.stdout.write(l); sys.stdout.flush(); time.sleep(0.02); continue
        s.send('USER$' + username); time.sleep(1)
        s.send('PASSWD$' + passwd)
    except:
        delay('[\033[92m+\033[0m] Connecting to server...........................[\033[1;91mFAILED\033[0m]')

    delay('Registration........................................[\033[1;92mCOMPLETE\033[0m]\n\t[\0331;[95m!\033[0m] Could not connect to %s:%i' % (ip, port))

def logon():
    delay('\t[\033[91m!\033[0m] ERROR: Comming Soon!\n')

    # Login not yet finished! Might even be removed, so don't even bother..
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)

    username = raw_input('Username: ')
    passwd = getpass.getpass('Password: ')

    if os.path.isfile('default.txt'):
        with open('default.txt') as f:
            split = f.readline()
            split = split.split(':')
            ip = split[0]; port = int(split[1])
    else:
        ip = raw_input('IP address: ')
        port = raw_input('Port: ')

    try:
        s.connect((ip, port))
        s.send('USER$' + username); time.sleep(1)
        s.send('PASSWD$' + passwd)

        # Await server response with "777" (OK) or "666" (NOT OK)
        while True:
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:
                if sock == s:
                    data = sock.recv(4096)
                    if data == '666':
                        msg = '[\033[92m+\033[0m] Authenticating to server...........................[\033[1;91mFAILED\033[0m]\n\t[\033[93m!\033[0m] Invalid username or password'
                        for l in msg:
                            sys.stdout.write(l); sys.stdout.flush(); time.sleep(0.02); continue
                        return logon()
                    elif data == '777':
                        msg = '[\033[92m+\033[0m] Authenticating to server...........................[\033[1;92mCOMPLETE\033[0m]\n\t[\033[93m!\033[0m] Welcome, %s' % username
                        for l in msg:
                            sys.stdout.write(l); sys.stdout.flush(); time.sleep(0.02); continue
                        return user_input()
    except:
        delay('[\033[92m+\033[0m] Connecting to server...........................[\033[1;91mFAILED\033[0m]')

def chat():
    if os.path.isfile('default.txt'):
        with open('default.txt') as f:
            split = f.readline(); f.close()
            split = split.split(':')
            ip = split[0]; port = int(split[1])
    else:
        ip = raw_input('IP: ')
        port = input('Port: ')
    username = raw_input('Username: ')
    if username == '':
        print('Username is required\n'); return chat()
    elif username.count('', 0) < 4:
        print('Your username must contain at least 4 characters\n'); return chat()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
    try:
        s.connect((ip, port))
        msg = '\033[1;92mCOMPLETE\033[0m'; result = 'Connected to'
    except:
        msg = '\033[1;91mFAILED\033[0m'; result = 'Failed to connect to'

    output = '''
    [\033[92m+\033[0m] Connecting to resistance network...........................[%s]
        [\033[93m!\033[0m] %s %s:%i

%s
''' % (msg, result, ip, port, logo)
    for l in output:
        sys.stdout.write(l); sys.stdout.flush()
        time.sleep(0.02); continue
    s.send('JOIN$' + username)
    sys.stdout.write('[' + username + '] '); sys.stdout.flush()

    while True:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

        for sock in read_sockets:
            if sock == s:
                data = sock.recv(4096)
                if not data:
                    print('Connection lost...'); return user_input()

                # Kick user [WARNING] NO ADMIN TOKEN REQUIRED
                elif '/kick ' + username in data:
                    print('\nConnection lost.................[\033[1;91mKicked\033[0m]'); return user_input()
                else:
                    sys.stdout.write('\033[92m' + data + '\033[0m')
                    sys.stdout.write('[' + username + '] '); sys.stdout.flush()
            else:
                msg = '[' + username + '] ' + sys.stdin.readline()
                #s.send('[' + grab_time() + '] ' + msg)
                s.send(msg)
                sys.stdout.write('[' + username + '] '); sys.stdout.flush()

def default():
    try:
        ip = raw_input('Set IP: ')
        port = raw_input('Set port: ')
        if not os.path.isfile('default.txt'):
            with open('default.txt', 'w+') as f:
                f.write(ip + ':' + port); f.close()
                delay('Default server is now %s:%s\n\tSaved to: ./default.txt\n' % (ip, port))
        else:
            delay('[!] ERROR - Remove current setting first with <del default>\n')
    except KeyboardInterrupt:
        print('\n'); return user_input()
    except Exception as e:
        delay('%s\n' % e)

def deldefault():
    try:
        os.remove('default.txt'); delay('\t[!] File ./default.txt successfully deleted\n')
    except Exception as e:
        delay('%s\n' % e)

def boot():
    if os.path.isfile('online.txt'):
        os.remove('online.txt')
    logging = raw_input('Enable logging? (y/n): ')
    if logging == 'y':
        logfile = grab_time() + '.txt'
        with open(logfile, 'w+') as f:
            f.write('# SERVER LOGS\n')
            f.close()

    admin_passwd = gen_string()
    with open('password.txt', 'w+') as f:
        f.write(admin_passwd)
        f.close()

    wl = raw_input('Allow whitelisted users only? (y/n): ')
    if wl == 'y':
        if not os.path.isfile('whitelist.txt'):
            cwl = raw_input('No whitelist found, create one now? (y/n)')
            if cwl == 'y':
                with open('whitelist.txt', 'w+') as f:
                    f.write('# ALLOWED IP ADDRESSES')
                    f.close()
                print('\nWrite "exit" to finish')
                while True:
                    addip = raw_input('IP to add: ')
                    if addip == 'exit':
                        return boot()
                    else:
                        with open('whitelist.txt', 'a') as f:
                            f.write('\n' + addip); f.close()


    if not os.path.isfile('default.txt'):
        port = 4546
    else:
        with open('default.txt') as f:
            split = f.readline()
            split = split.split(':')
            port = int(split[1])
            f.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    client_list.append(server)
    msg = '[!] Server is now running...\n\t[HOST] %s\n\t[PORT] %i\n\t[ADMIN KEY] %s\n' % (host, port, admin_passwd)
    for l in msg:
        sys.stdout.write(l); sys.stdout.flush()
        time.sleep(0.02); continue

    while True:
        read_rdy,write_rdy,in_error = select.select(client_list,[],[],0)
        for sock in read_rdy:
            if sock == server:
                sockfd, addr = server.accept()
                client_list.append(sockfd)

                # WARNING: Experimental, does not work properly!
                if wl == 'y':
                    for line in open('whitelist.txt'):
                        line = line.rstrip()
                        if line in addr:
                            msg = '[%s:%s] Connected\n' % addr
                        else:
                            msg = '[%s:%s] Refused\n' % addr
                            if sock in client_list:
                                client_list.remove(sock)
                            continue
                else:
                    msg = '[%s:%s] Connected\n' % addr

                if logging == 'y':
                    with open(logfile, 'a') as f:
                        f.write('[' + grab_time() + '] >> ' + msg)
                        f.close()
                for l in msg:
                    sys.stdout.write(l); sys.stdout.flush()
                    time.sleep(0.02); continue
                #broadcast(server, sockfd, '[%s:%s] Connected\n' % addr)
            else:
                try:
                    data = sock.recv(4096)
                    if data:
                        if 'JOIN$' in data:
                            user = data.split('$')

                            if not os.path.isfile('online.txt'):
                                with open('online.txt', 'w+') as f:
                                    f.write('# ONLINE USERS')
                                    f.close()
                            online = open('online.txt').read()
                            if user[1] in online:
                                broadcast(server, sockfd, 'User [%s] was kicked from the server > Username already taken\n' % user[1])
                                if logging == 'y':
                                    with open(logfile, 'a') as f:
                                        f.write('[' + grab_time() + '] >> User [%s] was kicked from the server> Username already taken' % user[1])
                                        f.close()
                                if sock in client_list:
                                    client_list.remove(sockfd)
                            else:
                                broadcast(server, sockfd, '\n[%s] Connected\n' % user[1])
                                with open('online.txt', 'a') as f:
                                    f.write('\n' + user[1])
                                    f.close()
                        elif 'PASSWD$' in data:
                            passwd = data.split('$')
                            passwd2 = open('password.txt').read()

                            if passwd[2] == passwd2:
                                broadcast(server, sock, '[SERVER] Root admin came online\n')

                        else:
                            broadcast(server, sock, '\r' + data)
                        if logging == 'y':
                            with open(logfile, 'a') as f:
                                f.write('[' + grab_time() + '] >> ' + data)
                                f.close()
                    else:
                        if sock in client_list:
                            client_list.remove(sock)
                            #broadcast(server, sock, '[%s:%s] left\n' % addr)
                            broadcast(server, sockfd, 'A user left the server\n')
                            if logging == 'y':
                                with open(logfile, 'a') as f:
                                    f.write('[' + grab_time() + '] >> ' + '[%s:%s] left\n' % addr)
                                    f.close()
                except KeyboardInterrupt:
                    try:
                        os.remove('online.txt')
                    except Exception as e:
                        msg = e
                        for l in msg:
                            sys.stdout.write(l); sys.stdout.flush(); time.sleep(0.02); continue
                    if logging == 'y':
                        with open(logfile, 'a') as f:
                            f.write('# END OF LOGS\n')
                            f.close()
                    server.close()
                    delay('''
        [\033[93m-\033[0m] Stopping all services...........................[\033[1;92mCOMPLETE\033[0m]

\033[95m>> Shutting down...\033[0m
''')
                except:
                    broadcast(server, sock, '[%s:%s] left\n' % addr)
                    if logging == 'y':
                        with open(logfile, 'a') as f:
                            f.write('[' + grab_time() + '] >> ' + '[%s:%s] left\n' % addr)
                            f.close()
                    continue
    if logging == 'y':
        with open(logfile, 'a') as f:
            f.write('# END OF LOGS\n')
            f.close()
    try:
        os.remove('online.txt')
    except Exception as e:
        msg = e
        for l in msg:
            sys.stdout.write(l); sys.stdout.flush(); time.sleep(0.02); continue
    server.close()

host = ''
if host == '':
    host = '127.0.0.1'
client_list = []

def broadcast(server, sock, message):
    for socket in client_list:
        if socket != server and socket != sock:
            try:
                socket.send(message)
            except Exception as e:
                socket.close()
                if socket in client_list:
                    client_list.remove(socket)

def grab_time():
    stamp = time.time()
    return datetime.datetime.fromtimestamp(stamp).strftime('%d-%m-%Y %H:%M:%S')

def kick(s):
    with open('online.txt', 'w') as f:
        cl_list = cl_list.replace(s + '\n', '')
        f.write(cl_list)
        f.close()

def ban(s):
    if not os.path.isfile('banlist.txt'):
        with open('banlist.txt', 'w+') as f:
            f.write('#BANNED USERS\n' + s)
            f.close()
    else:
        with open('banlist.txt', 'a') as f:
            f.write('\n' + s)
            f.close()

def gen_string(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if __name__ == "__main__":
    delay('Resistance Network [Version 0.1.7601]///////////////////////////////\n\n')
