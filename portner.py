import socket
import sys
from datetime import datetime

#color codes
bright_red = "\033[91m"
bright_green = "\033[92m"
bright_yellow = "\033[93m"
bright_cyan = "\033[96m"
reset = "\033[0m"



print(
    f"""
{bright_red}[DESCLIMER] {reset}: This port scanner tool is provided for educational and authorized testing purposes only.
The developer of this software takes no responsibility or liability for any misuse, damage, legal consequences, or unauthorized activity conducted using this tool.
{bright_green}[CREATED BY]{reset}: Virus9T
"""
)



#three parts 1. get the scanning info from the client, 2.trying to connect or pass 3. show results
#make a function of the main scanner that is going to run in a loop in the scanning function later the show the whole thing down below
nameofhost=input("[*]Enter the host name or the IP: ")
host=socket.gethostbyname(nameofhost)
print(f"{bright_green}[IP]{reset}{nameofhost}: {bright_green}{host}",reset)
start_port=int(input("[*]Enter the starting port: "))
end_port=int(input("[*]Enter the Ending port: "))


def send_payload_recv_banner(sock, port):
    """
    Sends a service detection payload to a given socket and port.
    Returns the banner if received, otherwise returns a fallback message.
    """
    payload_dict = {
        1: b"PROBE_PORT_1\r\n",
        7: b"PING\r\n",  # Echo
        9: b"NOPAYLOAD",  # Discard
        13: b"TIME?\r\n",  # Daytime
        17: b"QUOTE\r\n",  # QOTD
        19: b"ChargenTEST123\r\n",  # Chargen
        20: b"LIST\r\n",  # FTP-Data
        21: b"USER anonymous\r\nPASS guest@\r\n",  # FTP
        22: b"\r\n",  # SSH (version banner)
        23: b"\r\n",  # Telnet
        25: b"EHLO test.local\r\nMAIL FROM:<a@a.com>\r\n",  # SMTP
        26: b"EHLO smtp2\r\n",
        37: b"\r\n",  # TIME
        53: b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS query
        67: b"\x01",  # DHCP Discover
        68: b"\x01",  # DHCP Response
        69: b"file.txt\x00netascii\x00",  # TFTP RRQ
        70: b"/\r\n",  # Gopher
        79: b"nobody\r\n",  # Finger
        80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",  # HTTP
        81: b"HEAD / HTTP/1.0\r\n\r\n",  # Alternate HTTP
        88: b"\r\n",  # Kerberos
        110: b"USER test\r\nPASS test\r\n",  # POP3
        111: b"\x80\x00\x00\x00",  # Portmapper (RPC)
        113: b"USERID : UNIX : 12345 , 54321\r\n",  # Ident
        119: b"LIST\r\n",  # NNTP
        123: b"\x1b" + 47 * b"\0",  # NTP
        135: b"\x05\x00\x0b\x03\x10\x00\x00\x00",  # MS RPC
        137: b"\x80" + b"\x00" * 31,  # NetBIOS Name Query
        138: b"\x00",  # NetBIOS Datagram
        139: b"\x00",  # NetBIOS Session
        143: b"01 LOGIN root toor\r\n",  # IMAP
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\x13\x8f\x8d\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        # SNMP
        179: b"OPENBGP\r\n",  # BGP
        194: b"NICK scanner\r\nUSER scanner 0 * :Banner Grabber\r\n",  # IRC
        389: b"\x30\x1c\x02\x01\x01\x60\x17\x02\x01\x03\x04\x00\x80\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x03U\x04\x03\x0c\x02ab",
        # LDAP
        443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",  # HTTPS
        445: b"\xff\x53\x4d\x42",  # SMB
        465: b"EHLO secure.test\r\n",  # SMTPS
        500: b"\x00",  # ISAKMP
        512: b"id\r\n",  # exec
        513: b"whoami\r\n",  # login
        514: b"logger test\r\n",  # syslog
        520: b"\x00",  # RIP
        554: b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",  # RTSP
        587: b"EHLO relay.test\r\n",  # SMTP Submission
        593: b"\r\n",  # MS-RPC over HTTP
        631: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # IPP
        993: b"\r\n",  # IMAPS
        995: b"USER test\r\n",  # POP3S
        1080: b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00",  # SOCKS4 proxy handshake
        1194: b"\x38\x01\x00\x00",  # OpenVPN
        1234: b"HELLO\r\n",  # Often used in testing/debugging
        1433: b"\x12\x01\x00\x34\x00\x00\x00\x00MSSQL",  # SQL Server
        1521: b"\x00\x0a\x00\x00\x01\x00\x00\x00",  # Oracle TNS probe
        1701: b"\x00\x00\x00\x00",  # L2TP hello
        1723: b"\x1a\x2b\x3c\x4d",  # PPTP generic handshake
        1900: (
            """M-SEARCH * HTTP/1.1\r\n"
            "HOST:239.255.255.250:1900\r\n"
            "MAN:\"ssdp:discover\"\r\n"
            "MX:1\r\n"
            "ST:ssdp:all\r\n\r\n"""
        ).encode(),  # SSDP / UPnP discovery
        2000: b"\x01\x00\x00\x00",  # Cisco SCCP "hello" message
    }
    try:
        if port in payload_dict and payload_dict[port]:
            sock.send(payload_dict[port])
        else:
            generic_payload=(
            """  HEAD / HTTP/1.1\r\n
                "Host: localhost\r\n
                "User-Agent: Mozilla/5.0\r\n
                "Connection: close\r\n\r\n""").encode()
            sock.send(generic_payload)

        banner=sock.recv(2048).decode(errors="ignore").strip()
        return banner if banner else f"{bright_red}BANNER NOT FOUND"
    except Exception as e:
        return f"{bright_red}Some eroor occured while Grabbing the Banner--{e}{reset}"

def main_scanner():
            now=datetime.now()
            print(f"{bright_green}[START]{reset}Scanning For Open Ports In {host} Between {start_port} - {end_port} at {now.strftime("%Y-%m-%d %I:%M:%S %p")}\n")
            for port in range(start_port, end_port+1):
                sock = socket.socket()
                sock.settimeout(1)
                try:
                    sock.connect((host,port))
                    grabbed_banner=send_payload_recv_banner(sock, port)
                    print(f"{bright_green}[SUCCESS] PORT OPENED {port} : {bright_cyan}{grabbed_banner}{reset}")

                    #except:
                        #print(f"[+]PORT OPEN {port} : BANNER NOT FOUND")

                except ConnectionRefusedError:
                    sys.stdout.write(f"{bright_red}[REFUSED] PORT {port} : CLOSED{reset}")
                    sys.stdout.flush()
                    sys.stdout.write("\r"+""*80+"\r")
                    sys.stdout.flush()
                    pass
                except socket.timeout:
                    sys.stdout.write(f"{bright_yellow}[TIMEOUT] PORT {port}")
                    sys.stdout.flush()
                    sys.stdout.write("\r"+""*80+"\r")
                    sys.stdout.flush()
                    pass
                except OSError as exceptioin:
                    sys.stdout.write(f"[ERROR] OSException {port} : {exceptioin}\r")
                    sys.stdout.flush()
                    sys.stdout.write("\r" + "" * 80 + "\r")
                    sys.stdout.flush()
                    pass
#run the programme
if __name__== "__main__":
    main_scanner()
