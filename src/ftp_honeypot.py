import random
from twisted.internet import protocol, reactor, task
from twisted.protocols.basic import LineOnlyReceiver
import os
from logger import write_log
from analyze_logs import analyze_honeypot_logs, write_analysis_report

class FTPHoneypotProtocol(LineOnlyReceiver):
    delimiter = b'\r\n'

    def __init__(self):
        self.current_directory = "/"
        self.data_protocol = None
        self.data_factory = None
        self.passive_port = None
        self.username = None
        self.client_ip = None
        self.is_logged_in = False
        self.fs = {
            '/': {'dirs': set(['fake_dir']), 'files': {}},
            '/fake_dir': {'dirs': set(), 'files': {'file1.txt': 123, 'file2.txt': 456}}
        }

    def connectionMade(self):
        self.client_ip = self.transport.getPeer().host
        write_log({"event": "connection_made", "client": self.client_ip})
        self.sendLine(b"220 Welcome to FTP honeypot")

    def connectionLost(self, reason):
        write_log({"event": "connection_lost", "client": self.client_ip, "reason": str(reason)})
        if self.data_protocol:
            self.data_protocol.transport.loseConnection()
        self.data_protocol = None
        self.data_factory = None

    def lineReceived(self, line):
        line = line.decode()
        cmd, *args = line.strip().split()
        arg = " ".join(args) if args else ""
        cmd_upper = cmd.upper()

        write_log({
            "event": "command_received",
            "client": self.client_ip,
            "command": cmd_upper,
            "argument": arg,
        })

        if cmd_upper == "USER":
            if arg == "admin":
                self.username = arg
                self.sendLine(b"331 Username OK, need password")
                write_log({"event": "user_set", "client": self.client_ip, "username": self.username})
            else:
                self.sendLine(b"530 Invalid username")
                write_log({"event": "user_invalid", "client": self.client_ip, "username": arg})
            return
        if cmd_upper == "PASS":
            if self.username == "admin" and arg == "123456":
                self.is_logged_in = True
                self.sendLine(b"230 Login successful")
                write_log({"event": "login_success", "client": self.client_ip, "username": self.username})
            else:
                self.sendLine(b"530 Login incorrect")
                write_log({"event": "login_failed", "client": self.client_ip, "username": self.username})
            return

        if not self.is_logged_in:
            self.sendLine(b"530 Please login with USER and PASS")
            return

        if cmd_upper == "PWD":
            self.sendLine(f'257 "{self.current_directory}" is the current directory'.encode())
        elif cmd_upper == "CWD":
            self.handle_CWD(arg)
        elif cmd_upper == "PASV":
            self.handle_PASV()
        elif cmd_upper == "LIST":
            self.handle_LIST(arg)
        elif cmd_upper == "STOR":
            self.handle_STOR(arg)
        elif cmd_upper == "RETR":
            self.handle_RETR(arg)
        elif cmd_upper == "DELE":
            self.handle_DELE(arg)
        elif cmd_upper in ("MKD", "XMKD"):
            self.handle_MKD(arg)
        elif cmd_upper in ("RMD", "XRMD"):
            self.handle_RMD(arg)
        elif cmd_upper == "NOOP":
            self.sendLine(b"200 NOOP ok")
        elif cmd_upper == "WHOAMI":
            self.sendLine(f"200 You are: {self.username}".encode())
        elif cmd_upper == "HELP":
            cmds = "USER PASS PWD CWD LIST PASV STOR RETR DELE MKD RMD NOOP WHOAMI HELP QUIT"
            self.sendLine(b"214-Commands:")
            self.sendLine(cmds.encode())
            self.sendLine(b"214 End of HELP")
        elif cmd_upper == "QUIT":
            self.sendLine(b"221 Goodbye")
            write_log({"event": "quit", "client": self.client_ip})
            self.transport.loseConnection()
        else:
            self.sendLine(b"502 Command not implemented")

    def handle_CWD(self, path):
        prev = self.current_directory
        if path == "..":
            if self.current_directory != "/":
                self.current_directory = os.path.dirname(self.current_directory.rstrip('/')) or "/"
            self.sendLine(f'250 Directory changed to {self.current_directory}'.encode())
            write_log({"event": "cwd", "client": self.client_ip, "from": prev, "to": self.current_directory})
        else:
            new_dir = (self.current_directory.rstrip('/') + '/' + path).replace('//','/')
            if new_dir in self.fs:
                self.current_directory = new_dir
                self.sendLine(f'250 Directory changed to {self.current_directory}'.encode())
                write_log({"event": "cwd", "client": self.client_ip, "from": prev, "to": self.current_directory})
            else:
                self.sendLine(b"550 Directory not found")
                write_log({
                    "event": "cwd_failed",
                    "client": self.client_ip,
                    "argument": path
                })

    def handle_PASV(self):
        if self.data_protocol:
            self.sendLine(b"425 Data connection already open")
            return
        self.passive_port = random.randint(1024, 65535)
        factory = protocol.ServerFactory()
        factory.protocol = FTPDataProtocol
        factory.parent = self
        reactor.listenTCP(self.passive_port, factory)
        self.data_factory = factory

        ip = self.transport.getHost().host.replace('.', ',')
        p1 = self.passive_port // 256
        p2 = self.passive_port % 256
        self.sendLine(f"227 Entering Passive Mode ({ip},{p1},{p2})".encode())
        write_log({"event": "pasv", "client": self.client_ip, "port": self.passive_port})

    def handle_LIST(self):
        target = self.current_directory
        if path_arg:
            p = (self.current_directory.rstrip('/') + '/' + path_arg).replace('//','/')
            if p in self.fs:
                target = p
            else:
                self.sendLine(b"550 Directory not found")
                write_log({"event": "list_failed_no_dir", "client": self.client_ip, "argument": path_arg})
                return

        if not self.data_protocol:
            self.sendLine(b"425 No data connection")
            write_log({"event": "list_failed_no_data", "client": self.client_ip})
            return

        self.sendLine(b"150 Here comes the directory listing")
        write_log({"event": "list_start", "client": self.client_ip, "cwd": target})

        listing = ''
        entry_time = 'Apr 28 12:00'
        for d in sorted(self.fs[target]['dirs']):
            listing += f"drwxr-xr-x 1 owner group 0 {entry_time} {d}\r\n"
        for f, size in sorted(self.fs[target]['files'].items()):
            listing += f"-rw-r--r-- 1 owner group {size} {entry_time} {f}\r\n"

        self.data_protocol.transport.write(listing.encode())
        self.data_protocol.transport.loseConnection()
        self.data_protocol = None

        self.sendLine(b"226 Directory send OK")
        write_log({"event": "list_done", "client": self.client_ip, "cwd": target})

    def handle_STOR(self, filename):
        if not self.data_protocol:
            self.sendLine(b"425 No data connection for STOR")
            write_log({"event": "stor_failed_no_data", "client": self.client_ip})
            return
        self.sendLine(b"150 Ok to receive data")
        write_log({"event": "stor_start", "client": self.client_ip, "filename": filename})
        self.fs[self.current_directory]['files'][filename] = 0
        self.data_protocol.transport.loseConnection()
        self.data_protocol = None
        self.sendLine(b"226 Transfer complete")
        write_log({"event": "stor_done", "client": self.client_ip, "filename": filename})

    def handle_RETR(self, filename):
        if not self.data_protocol:
            self.sendLine(b"425 No data connection for RETR")
            write_log({"event": "retr_failed_no_data", "client": self.client_ip})
            return
        if filename not in self.fs[self.current_directory]['files']:
            self.sendLine(b"550 File not found")
            return
        self.sendLine(b"150 Opening data connection")
        write_log({"event": "retr_start", "client": self.client_ip, "filename": filename})
        content = f"Fake content of file {filename}\r\n"
        self.data_protocol.transport.write(content.encode())
        self.data_protocol.transport.loseConnection()
        self.data_protocol = None
        self.sendLine(b"226 Transfer complete")
        write_log({"event": "retr_done", "client": self.client_ip, "filename": filename})

    def handle_DELE(self, filename):
        if filename in self.fs[self.current_directory]['files']:
            del self.fs[self.current_directory]['files'][filename]
            self.sendLine(b"250 File deleted")
            write_log({"event": "dele", "client": self.client_ip, "filename": filename})
        else:
            self.sendLine(b"550 Permission denied")
            write_log({"event": "dele_failed", "client": self.client_ip, "filename": filename})

    def handle_MKD(self, dirname):
        new_path = (self.current_directory.rstrip('/') + '/' + dirname).replace('//','/')
        if dirname in self.fs[self.current_directory]['dirs'] or new_path in self.fs:
            self.sendLine(b"550 Directory exists")
            return
        self.fs[self.current_directory]['dirs'].add(dirname)
        self.fs[new_path] = {'dirs': set(), 'files': {}}
        self.sendLine(f'257 "{dirname}" created'.encode())
        write_log({"event": "mkd", "client": self.client_ip, "dirname": dirname})

    def handle_RMD(self, dirname):
        new_path = (self.current_directory.rstrip('/') + '/' + dirname).replace('//','/')
        if dirname in self.fs[self.current_directory]['dirs'] and not self.fs[new_path]['dirs'] and not self.fs[new_path]['files']:
            self.fs[self.current_directory]['dirs'].remove(dirname)
            del self.fs[new_path]
            self.sendLine(b"250 Directory removed")
            write_log({"event": "rmd", "client": self.client_ip, "dirname": dirname})
        else:
            self.sendLine(b"550 Permission denied")
            write_log({"event": "rmd_failed", "client": self.client_ip, "dirname": dirname})

class FTPDataProtocol(protocol.Protocol):
    def connectionMade(self):
        self.factory.parent.data_protocol = self
        print("Data connection established")

    def dataReceived(self, data):
        pass

    def connectionLost(self, reason):
        self.factory.parent.data_protocol = None
        print("Data connection closed")

class FTPHoneypotFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return FTPHoneypotProtocol()

def periodic_analysis():
    report = analyze_honeypot_logs()
    write_analysis_report(report)
def on_shutdown():
    report = analyze_honeypot_logs()
    write_analysis_report(report)

if __name__ == "__main__":
    reactor.listenTCP(21, FTPHoneypotFactory())
    print("FTP honeypot running on port 21...")
    lc = task.LoopingCall(periodic_analysis)
    lc.start(300.0)
    
    reactor.addSystemEventTrigger('after', 'shutdown', on_shutdown)
    
    reactor.run()
