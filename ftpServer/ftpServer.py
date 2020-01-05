#
# Small FTP server for ESP8266 ESP32 in Micropython and Python 3.7
# Based on the work of Chrisgp - Christopher Popp and Pfalcon - Paul Sokolovsky
#
# The server accepts active and passive mode. It runs in the background. and uses thread
# Start the server with:
#
# import ftpServer
# ftpServer = FtpServer (21, "192.168.1.130")
#
# port is the port number (default 21)
# ipAdresser is the address of the FTP server is used for active mode
#
# Copyright (c) 2016 Christopher Popp (original FTP server framework)
# Copyright (c) 2016 Paul Sokolovsky (control structure for the background execution)
# Copyright (c) 2016 Robert Hammelrath (put the parts together and a few extensions)
# Copyright (c) 2020 Peter Müller conversion for Thread and active and passive mode
# Distributed under MIT license
#

import os
import socket
import sys
import time

import _thread

_DATA_PORT = 13333
log_level = 4


class Tool:
    # compare fname against pattern. Pattern may contain
    # the wildcards ? and *.
    def _fncmp(self, fname, pattern):
        pi = 0
        si = 0
        while pi < len(pattern) and si < len(fname):
            if (fname[si] == pattern[pi]) or (pattern[pi] == '?'):
                si += 1
                pi += 1
            else:
                if pattern[pi] == '*':  # recurse
                    if pi == len(pattern.rstrip("*?")):  # only wildcards left
                        return True
                    while si < len(fname):
                        if self._fncmp(fname[si:], pattern[pi + 1:]):
                            return True
                        else:
                            si += 1
                    return False
                else:
                    return False
        if pi == len(pattern.rstrip("*")) and si == len(fname):
            return True
        else:
            return False

    def _get_absolute_path(self, cwd, payload):
        # Just a few special cases "..", "." and ""
        # If payload start's with /, set cwd to /
        # and consider the remainder a relative path
        if payload.startswith('/'):
            cwd = "/"
        for token in payload.split("/"):
            if token == '..':
                cwd = self._split_path(cwd)[0]
            elif token != '.' and token != '':
                if cwd == '/':
                    cwd += token
                else:
                    cwd = cwd + '/' + token
        return cwd.replace('\n', '')

    def _make_description(self, path, fname, full):
        if full:
            stat = os.stat(self._get_absolute_path(path, fname))
            file_permissions = ("drwxr-xr-x"
                                if (stat[0] & 0o170000 == 0o040000)
                                else "-rw-r--r--")
            file_size = stat[6]
            tm = time.localtime(stat[7])
            if tm[0] != time.localtime()[0]:
                description = "{} 1 owner group {:>10} {} {:2} {:>5} {}\r\n".\
                    format(file_permissions, file_size,
                           self._month_name[tm[1]], tm[2], tm[0], fname)
            else:
                description = "{} 1 owner group {:>10} {} {:2} {:02}:{:02} {}\r\n".\
                    format(file_permissions, file_size,
                           self._month_name[tm[1]], tm[2], tm[3], tm[4], fname)
        else:
            description = fname + "\r\n"
        return description.encode()

    def _split_path(self, path):  # instead of path.rpartition('/')
        tail = path.split('/')[-1]
        head = path[:-(len(tail) + 1)]
        return ('/' if head == '' else head, tail)

    def _num_ip(self, ip):
        items = ip.split(".")
        return (int(items[0]) << 24 | int(items[1]) << 16 |
                int(items[2]) << 8 | int(items[3]))

    def _osStat(self, path):
        return os.stat(path)

    def _osRemove(self, path):
        os.remove(path)

    def _osRename(self, fromname, path):
        os.rename(fromname, path)
        

    def _osRmdir(self, path):
        os.rmdir(path)

    def _osMkdir(self, path):
        os.mkdir(path)

    def _osListdir(self, path):
        return os.listdir(path)


class FtpServer(Tool):

    def __init__(self, port=21, severIP="0.0.0.0"):
        _thread.start_new_thread(self._run, (port, severIP))

    def _run(self, port, severIP):
        import socket
        ftpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ftpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ftpsocket.bind(('0.0.0.0', port))
        ftpsocket.listen(5)

        datasocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        datasocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        datasocket.bind(('0.0.0.0', _DATA_PORT))
        datasocket.listen(5)

        log_msg(1, "FTP Server started on:", severIP, " Port: ", port)
        if severIP == '0.0.0.0':
            print("configure the FTP Server ")

        while True:
            conn, addr = ftpsocket.accept()
            self._loop(conn, addr, severIP,datasocket)

    def _loop(self, conn, addr, severIP,datasocket):
        file = conn.makefile('rwb')
        ftpClient = FTP_client(file, addr, severIP, datasocket)
        _thread.start_new_thread(self._ausf, (ftpClient,))

    def _ausf(self, ftpClient):
        __a = True
        while __a:
            __a = ftpClient._exec_ftp_command()


class Socket(Tool):

    _CHUNK_SIZE = 1024

    def __init__(self, file):
        self.__file = file

    def _readline(self):
        try:
            str = self.__file.readline()
            str = str.decode('utf-8')
            str = str.replace("\r", "")
            str = str.replace("\n", "")
            log_msg(2, "->: {}".format(str))
            return str
        except Exception as e:
            log_msg(1, "->: {}".format(e))
            return ""

    def _writeln(self, str):
        log_msg(2, "<-: {}".format(str))
        str = str+"\r\n"
        self.__file.write(str.encode())
        if (not sys.implementation.name == "micropython"):
            self.__file.flush()

    def _close(self):
        self.__file._close()

    def _send_list_data(self, path, data_client, full):
        try:
            for fname in self._osListdir(path):
                data_client.sendall(self._make_description(path, fname, full))
        except Exception as e:
            sys.print_exception(e)  # path may be a file name or pattern
            path, pattern = self._split_path(path)
            try:
                for fname in self._osListdir(path):
                    if self._fncmp(fname, pattern):
                        data_client.sendall(
                            self._make_description(path, fname, full))
            except Exception as e:
                sys.print_exception(e)
                pass

    def _send_file_data(self, path, data_client):
        with open(path, "rb") as file:
            chunk = file.read(self._CHUNK_SIZE)
            while len(chunk) > 0:
                data_client.sendall(chunk)
                chunk = file.read(self._CHUNK_SIZE)
            data_client.close()

    def _save_file_data(self, path, data_client, mode):
        with open(path, mode) as file:
            chunk = data_client.recv(self._CHUNK_SIZE)
            while len(chunk) > 0:
                file.write(chunk)
                chunk = data_client.recv(self._CHUNK_SIZE)
            data_client.close()

    def _open_dataclient(self):
        if self._status._isActiv():  # active mode
            data_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_client.connect(
                (self._status._getActDataAddr(), self._status._getDataPort()))
            log_msg(1, "FTP Data connection with:",
                    self._status._getActDataAddr())
        else:  # passive mode
            data_client,data_addr = self._status._getDataSocket().accept()
            log_msg(1, 1, "FTP Data connection with:", data_addr[0])
        return data_client


class Status:

    def __init__(self):
        self.__dataPort = _DATA_PORT
        self.__cwd = '/'
        self.__pasDataAddr = ''
        self.__actDataAddr = ''
        self.__remoteAddr = ''
        self.__activ = True
        self.__busy = False
        self.__commandTimeout = 300
        self.__dataSocket = None

    def _setDataPort(self, dataPort):
        self.__dataPort = dataPort

    def _getDataPort(self):
        return self.__dataPort

    def _getDataPortH(self):
        return self.__dataPort >> 8

    def _getDataPortL(self):
        return self.__dataPort % 256

    def _setCWD(self, cwd):
        self.__cwd = cwd

    def _getCWD(self):
        return self.__cwd

    def _setPasDataAddr(self, pasDataAddr):
        self.__pasDataAddr = pasDataAddr

    def _getPasDataAddr(self):
        return self.__pasDataAddr

    def _setActsDataAddr(self, actDataAddr):
        self.__actDataAddr = actDataAddr

    def _getActDataAddr(self):
        return self.__actDataAddr

    def _setRemoteAddr(self, remoteAddr):
        self.__remoteAddr = remoteAddr

    def _getRemoteAddr(self):
        return self.__remoteAddr

    def _setActiv(self, activ):
        self.__activ = activ

    def _isActiv(self):
        return self.__activ

    def _setBusy(self, busy):
        self.__busy = busy

    def _isBusy(self):
        return self.__busy

    def _getCommandTimeout(self):
        return __commandTimeout

    def _setDataSocket(self, dataSocket):
        self.__dataSocket = dataSocket

    def _getDataSocket(self):
        return self.__dataSocket


class FtpCommand(Socket):

    _month_name = ("", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    def __init__(self, file):
        super().__init__(file)
        self._writeln("220 , this is the {} Ftp.".format(
            sys.implementation.name))
        self._status = Status()

    def _USER(self):
        self._writeln("230 Logged in.")

    def _PASS(self):
        self._writeln("230 Logged in.")

    def _SYST(self):
        self._writeln("215 UNIX Type: L8")

    def _TYPE(self):
        self._writeln("200 OK")

    def _NOOP(self):
        self._writeln("200 OK")

    def _ABOR(self):
        self._writeln("200 OK")

    def _QUIT(self):
        self._writeln("221 Bye.")
        self._close()

    def _PWD(self):
        self._writeln('257 "{}"'.format(self._status._getCWD()))

    def _XPWD(self):
        self._writeln('257 "{}"'.format(self._status._getCWD()))

    def _CWD(self, path):
        try:
            if (self._osStat(path)[0] & 0o170000) == 0o040000:
                self._status._setCWD(path)
                self._writeln('250 OK')
            else:
                self._writeln('550 Fail')
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _XCWD(self, path):
        return self._CWD(path)

    def _PASV(self):
        self._writeln('227 Entering Passive Mode ({},{},{}).'.format(
            self._status._getPasDataAddr().replace('.', ','),
            self._status._getDataPortH(),
            self._status._getDataPortL()))
        self._status._setActiv(False)

    def _PORT(self, payload):
        items = payload.split(",")
        if len(items) >= 6:
            self._status._setActsDataAddr('.'.join(items[:4]))
            if self._status._getActDataAddr() == "127.0.0.1":
                # replace by command session addr
                self._status._setActsDataAddr(self._status._getRemoteAddr())
            self._status._setDataPort(int(items[4]) * 256 + int(items[5]))

            self._writeln('200 OK')
        else:
            self._writeln('504 Fail')

    def _LIST(self, payload, command):
        if payload.startswith("-"):
            option = payload.split()[0].lower()
            path = self._get_absolute_path(
                self._status._getCWD(), payload[len(option):].lstrip())
        else:
            path = self._get_absolute_path(self._status._getCWD(), payload)
            option = ""
        try:
            data_client = self._open_dataclient()
            self._writeln("150 Directory listing:")
            self._send_list_data(path, data_client, command ==
                                "LIST" or 'l' in option)
            self._writeln("226 Done.")
            data_client.close()
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')
            if data_client is not None:
                data_client.close()

    def _NLIST(self, payload, command):
        self._LIST(payload, command)

    def _RETR(self, path):
        try:
            data_client = self._open_dataclient()
            self._writeln("150 Opened data connection.")
            self._send_file_data(path, data_client)
            # if the next statement is reached,
            # the data_client was closed.
            data_client.close()
            self._writeln("226 Done.")
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')
            if data_client is not None:
                data_client.close()

    def _STOR(self, path, command):
        try:
            data_client = self._open_dataclient()
            self._writeln("150 Opened data connection.")
            self._save_file_data(path, data_client,
                                "wb" if command == "STOR" else "ab")
            # if the next statement is reached,
            # the data_client was closed.
            data_client.close()
            self._writeln("226 Done.")
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')
            if data_client is not None:
                data_client.close()

    def _APPE(self, path, command):
        self._STOR(path, command)

    def _SIZE(self, path):
        try:
            self._writeln('213 {}'.format(self._osStat(path)[6]))
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _STAT(self, payload, path):
        if payload == "":
            self._writeln("211-Connected to ({})\r\n"
                         "    Data address ({})\r\n"
                         "    TYPE: Binary STRU: File MODE: Stream\r\n"
                         "    Session timeout {}\r\n"
                         "211 Client count is {}\r\n".format(
                             self._status._getRemoteAddr(),
                             self._status._getPasDataAddr(),
                             self._status._getCommandTimeout()))
        else:
            self._writeln("213-Directory listing:")
            self._send_list_data(path, self._file, True)
            self._writeln("213 Done.")

    def _DELE(self, path):
        try:
            self._osRemove(path)
            self._writeln('250 OK')
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _RNFR(self, path):
        try:
            # just test if the name exists, exception if not
            self._osStat(path)
            self._fromname = path
            self._writeln("350 Rename from")
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _RNTO(self, path):
        try:
            self._osRename(self._fromname, path)
            self._writeln('250 OK')
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')
        self._fromname = None

    def _CDUP(self):
        self._status._setCWD(self._get_absolute_path(
            self._status._getCWD(), ".."))
        self._writeln('250 OK')

    def _XCUP(self):
        self._CDUP()

    def _RMD(self, path):
        try:
            self._osRmdir(path)
            self._writeln('250 OK')
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _XRMD(self, path):
        self._RMD(path)

    def _MKD(self, path):
        try:
            self._osMkdir(path)
            self._writeln('250 OK')
        except Exception as e:
            sys.print_exception(e)
            self._writeln('550 Fail')

    def _XMKD(self, path):
        self._MKD(path)

    def _MDTM(self,path):
        self._osMkdir(path)
        self._writeln('250 OK')

    def _NONE(self):
        self._writeln("502 Unsupported command")
    



class FTP_client(FtpCommand):

    def __init__(self, file, addr, serverAddress, datasocket):
        super().__init__(file)
        self._status._setRemoteAddr(addr[0])
        self._status._setActsDataAddr(addr[0])
        self._status._setPasDataAddr(serverAddress)
        self._status._setDataSocket(datasocket)
        log_msg(1, "FTP Command connection from: {}".format(
            self._status._getRemoteAddr()))

    def _exec_ftp_command(self):
        try:
            data = self._readline()
            if len(data) <= 0:
                # No data, _close
                # This part is NOT CLEAN; there is still a chance that a
                # closing data connection will be signalled as closing
                # command connection
                log_msg(1,  "*** No data, assume QUIT")
                return False

            if self._status._isBusy():  # check if another client is busy
                self._writeln("400 Device busy.")  # tell so the remote client
                return False
            self._status._setBusy(True)  # now it's my turn

            # check for log-in state may done here, like
            # if self.logged_in == False and not command in\
            #    ("USER", "PASS", "QUIT"):
            #    cl.sendall("530 Not logged in.\r\n")
            #    return

            command = data.split()[0].upper()
            payload = data[len(command):].lstrip()  # partition is missing
            path = self._get_absolute_path(self._status._getCWD(), payload)
            log_msg(
                1,  "Command={}, Payload={}".format(command, payload))
            if command == "USER":
                self._USER()
            elif command == "PASS":
                self._PASS()
            elif command == "SYST":
                self._SYST()
            elif command == "TYPE":
                self._TYPE()
            elif command == "NOOP":
                self._NOOP()
            elif command == "ABOR":
                self._ABOR()
            elif command == "QUIT":
                self._QUIT()
            elif command == "PWD":
                self._PWD()
            elif command == "XPWD":
                self._XPWD()
            elif command == "CWD":
                self._CWD(path)
            elif command == "XCWD":
                self._XCWD()
            elif command == "PASV":
                self._PASV()
            elif command == "PORT":
                self._PORT(payload)
            elif command == "LIST":
                self._LIST(payload, command)
            elif command == "NLST":
                self._NLIST(payload, command)
            elif command == "RETR":
                self._RETR(path)
            elif command == "STOR":
                self._STOR(path, command)
            elif command == "APPE":
                self._APPE()
            elif command == "SIZE":
                self._SIZE(path)
            elif command == "STAT":
                self._STAT(payload)
            elif command == "DELE":
                self._DELE(path)
            elif command == "RNFR":
                self._RNFR(path)
            elif command == "RNTO":
                self._RNTO(path)
            elif command == "CDUP":
                self._CDUP()
            elif command == "XCUP":
                self._XCUP()
            elif command == "RMD":
                self._RMD(path)
            elif command == "XRMD":
                self._XRMD(path)
            elif command == "MKD":
                self._MKD(path)
            elif command == "XMKD":
                self._XMKD(path)
            else:
                self._NONE()
        except Exception as err:
            sys.print_exception(err)
            log_msg(1,  "Exception in _exec_ftp_command: {}".format(err))
        # tidy up before leaving
        self._status._setBusy(False)
        return True


def log_msg(level, *args):
    if log_level >= level:
        print('ftpServer: ', *args)
