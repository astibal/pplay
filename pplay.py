#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import time
import socket
import time
import difflib
import re
import argparse
import fileinput
import binascii
import datetime
import pprint
import atexit

from scapy.all import *
from select import select

have_paramiko = False
have_colorama = False
have_ssl = False

option_dump_received_correct = False;
option_dump_received_different = True;
option_auto_send = 5

pplay_version = "1.7.0"

#EMBEDDED DATA BEGIN
#EMBEDDED DATA END

title='pplay - application payload player - %s' % (pplay_version,)
copyright="written by Ales Stibal <astib@mag0.net> (c) 2014"


g_script_module = None
g_delete_files = []

g_hostname = socket.gethostname()

## try to import colorama, indicate with have_ variable
try:
    import colorama
    from colorama import Fore, Back, Style
    
    have_colorama = True
except ImportError, e:
    print('No colorama, enjoy.',file=sys.stderr)
    
    
# try to import ssl, indicate with have_ variable
try:
    import ssl
    have_ssl = True
except ImportError, e:
    print('No SSL support!',file=sys.stderr)


# try to import paramiko, indicate with have_ variable

try:
    import paramiko
    have_paramiko = True
except ImportError, e:
    print('No paramiko support, use ssh with pipes!',file=sys.stderr)



def str_time():
    t = None
    failed = False
    try:
        t = datetime.now()
    except AttributeError, e:
        failed = True
    
    if not t and failed:
        try:
            t = datetime.datetime.now()
        except Exception, e:
            t = "<?>"
    
    return socket.gethostname() + "@" + str(t)

def print_green_bright(what):
    if have_colorama:
        print(Fore.GREEN + Style.BRIGHT + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_green(what):
    if have_colorama:
        print(Fore.GREEN + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)


def print_yellow_bright(what):
    if have_colorama:
        print(Fore.YELLOW + Style.BRIGHT + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_yellow(what):
    if have_colorama:
        print(Fore.YELLOW + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_red_bright(what):
    if have_colorama:
        print(Fore.RED + Style.BRIGHT + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_red(what):
    if have_colorama:
        print(Fore.RED + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_white_bright(what):
    if have_colorama:
        print(Fore.WHITE + Style.BRIGHT + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)

def print_white(what):
    if have_colorama:
        print(Fore.WHITE + what + Style.RESET_ALL,file=sys.stderr)
    else:
        print(what,file=sys.stderr)



__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""

def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % ord(x) for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)

def colorize(s,keywords):
    t = s
    for k in keywords:
        t = re.sub(k, Fore.CYAN+Style.BRIGHT+k+Fore.RESET+Style.RESET_ALL,t)
        
    return t

#print_green_bright("TEST%d:%s" % (12,54))

class Repeater:

    def __init__(self,fnm,server_ip):
        
        self.fnm = fnm
        
        self.packets = []
        self.origins = {}
        
        # write this data :)
        self.to_send = ''
        
        # list of indexes in packets
        self.origins['client'] = []
        self.origins['server'] = []
        
        self.server_port = 0
        self.custom_ip = server_ip
        
        self.whoami = ""
        
        # index of our origin
        self.packet_index = 0
        
        # index of in all packets regardless of origin
        self.total_packet_index = 0
        
        
        self.use_ssl = False
        self.sslv = 0
        self.ssl_context = None
        self.ssl_cipher = None
        self.ssl_sni = None
        self.ssl_alpn = None
        self.ssl_ecdh_curve = None
        self.ssl_cert = None
        self.ssl_key = None
        

        self.tstamp_last_read = 0
        self.tstamp_last_write = 0
        self._last_countdown_print = 0

        self.scripter = None
        
        self.exitoneot = False
        self.nostdin = False
        self.nohexdump = False
        
        self.omexit = False
        

        self.is_udp = False
        
        # our peer (ip,port)
        self.target = (0,0)


        # countdown timer for sending
        self.send_countdown = 0

    def load_scripter_defaults(self):
        global g_delete_files
        
        import tempfile
        
        if self.scripter:
            self.server_port = self.scripter.server_port
            self.packets = self.scripter.packets
            self.origins = self.scripter.origins


            has_cert = False
            try:
                if self.scripter.ssl_cert and self.scripter.ssl_key:
                    has_cert = True
            except Exception, e:
                print ("Script ssl certs: %s" % str(e))
            
            if has_cert:
                if self.scripter.ssl_cert and not self.ssl_cert:
                    h,fnm = tempfile.mkstemp()
                    o = os.fdopen(h,"w")
                    o.write(self.scripter.ssl_cert)
                    o.close()
                    
                    self.ssl_cert = fnm
                    g_delete_files.append(fnm)
                    
                if self.scripter.ssl_key and not self.ssl_key:
                    h,fnm = tempfile.mkstemp()
                    o = os.fdopen(h,"w")
                    o.write(self.scripter.ssl_key)
                    o.close()
                    
                    self.ssl_key = fnm
                    g_delete_files.append(fnm)
                
                
            

    def list_pcap(self, verbose=True):
        
        flows = {}
        ident = {}
        frame = -1
        
        print_yellow(">>> Connection list:")
        s = rdpcap(self.fnm)
        for i in s:
            
            frame+=1
            
            try:
                sip = i[IP].src
                dip = i[IP].dst
            except IndexError, e:
                # not even IP packet
                continue
            
            proto = "TCP"

            sport = ""
            dport = ""

            # TCP
            try:
                sport = str(i[TCP].sport)
                dport = str(i[TCP].dport)
            except IndexError, e:
                proto = "UDP"
               
            # UDP
            if proto == "UDP":
                try:
                    sport = str(i[UDP].sport)
                    dport = str(i[UDP].dport)
                except IndexError, e:
                    proto = "Unknown"
                  
                  
            # Unknown
            if proto == "Unknown":
                    continue
            

            key = proto+" / "+sip+":"+sport+" -> "+dip+":"+dport
            ident1 = sip+":"+sport
            ident2 = dip+":"+dport
            
            if key not in flows:
                if verbose:
                    print_yellow("%s (starting at frame %d)" % (key,frame))
                flows[key] = "yes"
                ident[ident1] = proto
                ident[ident2] = proto
                
        print_yellow("\n>>> Usable connection IDs:")
        for unique_ident in ident.keys():
            print_yellow(unique_ident)
                
                


    def read_pcap(self,im_ip, im_port):

        s = rdpcap(self.fnm)

        #print("Looking for client connection %s:%s" % (im_ip,im_port))

        for i in s:
            
            try:
                sip = i[IP].src
                dip = i[IP].dst
                sport = str(i[TCP].sport)
                dport = str(i[TCP].dport)
            except IndexError,e:
                # IndexError: Layer [TCP|IP] not found
                continue

            #print ">>> %s:%s -> %s:%s" % (sip,sport,dip,dport)


            origin = None

            if sip == im_ip and sport == im_port:
                origin = "client"
                if self.server_port == 0: 
                   self.server_port = dport                
                
            elif dip == im_ip and dport == im_port:
                origin = "server"
                
        
            if origin:
                p = i[TCP].payload
                if len(p) == 0:
                    #print "No payload"
                    continue
                
                #print("--")
                #print("Len: %s",help(p))
                if type(p) == type(Padding):
                    print("... reached end of tcp, frame contains padding")
                #print(hexdump(str(p)))
                
                current_index = len(self.packets)
                
                self.packets.append(p)
                self.origins[origin].append(current_index)
               
                #print "%s payload:\n>>%s<<" % (origin,p,)


    def read_smcap(self, im_ip, im_port):
        file_packets = []

        self.packets = []
        self.origins["client"] = []
        self.origins["server"] = []
        
        this_packet_origin = None
        this_packet_index = 0
        this_packet_bytes = []

        have_connection = False
        
        fin = fileinput.input(files=[self.fnm,])
        for line in fin:
            #print_yellow("Processing: " + line.strip())
            
            re_packet_start = re.compile(r'^\+\d+: +([^:]+):([^:]+)-([^:]+):([^:(]+)')
            re_packet_content_client = re.compile(r'^>\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')
            re_packet_content_server = re.compile(r'^ +<\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')
            
            sip = None
            dip = None
            sport = None
            dport = None

            if not have_connection:
                m = re_packet_start.search(line)
                if m:
                    #print_yellow_bright("Packet start: " + line.strip())
                    sip = m.group(1)
                    dip = m.group(3)
                    sport = m.group(2)
                    dport = m.group(4)
                    #print_yellow_bright("%s:%s -> %s:%s" % (sip,sport,dip,dport))
                    have_connection = True

                    self.server_port = dport
                    
                    if sip.startswith("udp_"):
                        self.is_udp = True


            matched = False
            m = None
            
            if not matched:
                m = re_packet_content_client.search(line)
                if m:
                    #print_green_bright(line.strip())
                    #print_green(m.group(2))
                    this_packet_bytes.append(m.group(2))
                    this_packet_origin = 'client'
                    matched = True
            
            if not matched:
                m = re_packet_content_server.search(line)
                if m:
                    #print_red(m.group(2))
                    this_packet_bytes.append(m.group(2))
                    this_packet_origin = 'server'
                    matched = True
            
            if not matched:
                if this_packet_bytes:
                    #finalize packet


                    data = self.smcap_convert_lines_to_bytes(this_packet_bytes)
                    if this_packet_origin == 'client':
                        #print_green("# Converted: -->\n%s\n#<--" % (data,))
                        self.packets.append(data)
                        self.origins['client'].append(this_packet_index)
                    else:
                        #print_red("# Converted: -->\n%s\n#<--" % (data,))
                        self.packets.append(data)
                        self.origins['server'].append(this_packet_index)

                    this_packet_bytes = []
                    this_packet_origin = None
                    this_packet_index += 1

        

    def smcap_convert_lines_to_bytes(this, list_of_ords):
        bytes = ''
        
        for l in list_of_ords:
            for oord in l.split(" "):
                if oord:
                    bytes += binascii.unhexlify(oord)
                    
        return bytes

    def list_smcap(self,args=None):
        
        fin = fileinput.input(files=[self.fnm,])
        for line in fin:
            re_packet_start = re.compile(r'^\+\d+: ([^:]+):([^:]+)-([^:]+):([^:(]+)')
           
            sip = None
            dip = None
            sport = None
            dport = None
            have_connection = False
            
            
            if not have_connection:
                m = re_packet_start.search(line)
                if m:
                    #print_yellow_bright("Packet start: " + line.strip())
                    sip = m.group(1)
                    dip = m.group(3)
                    sport = m.group(2)
                    dport = m.group(4)
                    
                    if sip.startswith("udp_"):
                        self.is_udp = True
                    
                    fin.close()
                    
                    n = sip.find("_")
                    if n >= 0 and n < len(sip) - 1:
                        sip = sip[n+1:]
                        
                    n = dip.find("_")
                    if n >= 0 and n < len(dip) - 1:
                        dip = dip[n+1:]
                    
                    if args:
                        if args == "sip":
                            print("%s" % (sip,),file=sys.stderr)
                            return sip
                        elif args == "dip":
                            print("%s" % (dip,),file=sys.stderr)
                            return dip
                        elif args == "sport":
                            print("%s" % (sport,),file=sys.stderr)
                            return sport
                        elif args == "dport":
                            print("%s" % (dport,),file=sys.stderr)
                            return dport
                        elif args == "proto":
                            if self.is_udp:
                                print("udp",file=sys.stderr)
                                return "udp"
                            else:
                                print("tcp",file=sys.stderr)
                                return "tcp"
                    
                    else:
                        print_yellow("%s:%s -> %s:%s  (single connection per file in smcap files)" % (sip,sport,dip,dport))
                        return "%s:%s" % (sip,sport)
             
             
    def export_self(self,efile):
        
        ssource = self.export_script(None)
        out = ''

        
        with open(__file__) as f: 
            lines = f.read().split('\n')
            
            for l in lines:
                out += l
                out += "\n"
                #print("export line: %s" % (l))
                if l == "#EMBEDDED DATA BEGIN":
                    out += "\n"
                    out += ssource
                    out += "\n"
                    
                    import hashlib
                    out += "pplay_version = \"" + str(pplay_version) + "-" + hashlib.sha1(ssource).hexdigest() + "\"\n"

                    
        with open(efile,"w") as o:
            o.write(out)
            #print_red("pack: using " + efile)
            
            
                
                
    def export_script(self,efile):
        
        c = "__pplay_packed_source__ = True\n\n\n\n"
        c += "class PPlayScript:\n\n"
        c += "    def __init__(self,pplay):\n"
        c += "        # access to pplay engine\n"
        c += "        self.pplay = pplay\n\n"
        c += "        self.packets = []\n"
        for p in self.packets:
            c += "        self.packets.append(%s)\n\n" % repr(str(p),)
        
        c += "        self.origins = {}\n\n"
        c += "        self.server_port = %s\n" % (self.server_port,)
        for k in self.origins.keys():
            c+= "        self.origins['%s']=%s\n" % (k,self.origins[k])
            
        c+="\n\n"
        if self.ssl_cert:
            with open(self.ssl_cert) as ca_f:
                c += "        self.ssl_cert=\"\"\"\n" + ca_f.read() + "\n\"\"\"\n"
                
        if self.ssl_key:
            with open(self.ssl_key) as key_f:
                c += "        self.ssl_key=\"\"\"\n" + key_f.read() + "\n\"\"\"\n"
                
        c+="\n\n"
        c+="""
    def before_send(self,role,index,data):
        # when None returned, no changes will be applied and packets[ origins[role][index] ] will be used
        return None

    def after_received(self,role,index,data):
        # return value is ignored: use it as data gathering for further processing
        return None
        """
        
        
        
        if efile == None:
            return c
        
        f = open(efile,'w')
        f.write(c)
        f.close()
        
        return None

    # for spaghetti lovers
    def impersonate(self,who):
        
        if who == "client":
            self.impersonate_client()
        elif who == "server":
            self.impersonate_server()
    
    def send_aligned(self):
        
        if self.packet_index < len(self.origins[self.whoami]):
            return self.total_packet_index >= self.origins[self.whoami][self.packet_index]
        return False

    def send_issame(self):
        if self.packet_index < len(self.origins[self.whoami]):
            return self.packets[self.origins[self.whoami][self.packet_index]] == self.to_send
        return False
    
    def ask_to_send(self,xdata=None):
            
        data = None
        if xdata == None:
            data = self.to_send
        else:
            data = xdata
        
        aligned = ''
        if self.send_aligned():
            aligned = '(in-sync'
        else:
            aligned = '(off-sync'
        
        if not self.send_issame():
            if aligned:
                aligned += ", modified"
            else:
                aligned += "(modified"
        
        if aligned:
            aligned+=") "
        
        
        out = "# [%d/%d]: %s" % (self.packet_index+1,len(self.origins[self.whoami]),aligned)
        if self.send_aligned():
            print_green_bright(out)
        else:
            print_yellow(out)
        
        out = ''
        if self.nohexdump:
            out = "# ... offer to send %dB of data (hexdump surpressed): " % (len(data),)
        else:
            out = hexdump(str(data))

        if self.send_aligned():
            print_green(out)
        # 
        #dont print hexdumps of unaligned data
        #else:
        #    print_yellow(out)
        
        
        if option_auto_send < 0 or option_auto_send >= 5:
            
            out = ''
            out += "#<--\n"
            out += "#--> SEND IT TO SOCKET? [ y=yes (default) | s=skip | c=CR | l=LF | x=CRLF ]\n"
            out += "#    For more commands or help please enter 'h'.\n"

            if self.send_aligned():
                print_green_bright(out)
            else:
                print_yellow(out)
                
                


    def ask_to_send_more(self):
        
        if not self.nostdin:
            print_yellow_bright("#--> SEND MORE INTO SOCKET? [ c=CR | l=LF | x=CRLF | N=new data]")
        #print_yellow_bright("#    Advanced: r=replace (vim 's' syntax: r/<orig>/<repl>/<count,0=all>)")


    def prepare_socket(self, s, server_side=False):
        if have_ssl and self.use_ssl:
            if not server_side:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                
                if self.sslv > 0:
                    sv = 3
                    self.ssl_context.options |= ssl.OP_NO_SSLv2
                    for v in [ssl.OP_NO_SSLv3, ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1, ssl.OP_NO_TLSv1_2 ]:
                        if sv == self.sslv:
                            sv = sv + 1
                            continue
                        
                        self.ssl_context.options |= v
                        sv = sv + 1
                        
                if self.ssl_cipher:
                    self.ssl_context.set_ciphers(self.ssl_cipher)
                    
                if self.ssl_alpn:
                    self.ssl_context.set_alpn_protocols(self.ssl_alpn)
                    
                return self.ssl_context.wrap_socket(s,server_hostname=self.ssl_sni,suppress_ragged_eofs=True)
            else:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                if self.sslv > 0:
                    sv = 3
                    self.ssl_context.options |= ssl.OP_NO_SSLv2
                    for v in [ ssl.OP_NO_SSLv3, ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1, ssl.OP_NO_TLSv1_2 ]:
                        if sv == self.sslv:
                            sv = sv + 1
                            continue
                        
                        self.ssl_context.options |= v
                        sv = sv + 1                

                if self.ssl_cipher:
                    self.ssl_context.set_ciphers(self.ssl_cipher)
                    
                if self.ssl_ecdh_curve:
                    self.ssl_context.set_ecdh_curve(self.ssl_ecdh_curve)
                
                self.ssl_context.load_cert_chain(certfile=self.ssl_cert,keyfile=self.ssl_key)
                return self.ssl_context.wrap_socket(s,server_side=True)                
        else:
            return s
                
        
    def impersonate_client(self):
        try:
            self.whoami = "client"
            
            
            s = None
            if  self.is_udp:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
            s = self.prepare_socket(s,False)
            
            ip = self.custom_ip
            port = int(self.server_port)
            
            t = ip.split(":")
            if len(t) > 1:
                ip = t[0]
                port = int(t[1])
                
            if port == 0:
                port = int(self.server_port)
                
            self.target = (ip,port)

            print_white_bright("IMPERSONATING CLIENT, connecting to %s:%s" % (ip,port))
            
            self.sock = s
            try:
                s.connect((ip,int(port)))
                self.packet_loop(self.sock)
                
            except socket.error,e:
                print_white_bright("Connection to %s:%s failed: %s" % (ip, port, e))
                return
            
            
        except KeyboardInterrupt, e:
            print_white_bright("\nCtrl-C: bailing it out.")
            return
    
    def impersonate_server(self):
        global g_script_module
        
        try:
            ip = "0.0.0.0"
            port = int(self.server_port)
            
            if self.custom_ip:
                
                t = self.custom_ip.split(":")
                if len(t) > 1:
                    ip = t[0]
                    port = int(t[1])
                        
                elif len(t) == 1:
                    # assume it's port
                    port = int(t[0])

                # if specified port is 0, use original port in the capture
                if port == 0:
                    port = int(self.server_port)
                
                #print("custom IP:PORT %s:%s" % (ip,port) )
                
            self.whoami = "server"
            print_white_bright("IMPERSONATING SERVER, listening on %s:%s" % (ip,port,))
            
            server_address = (ip, int(port))
            
            if  self.is_udp:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if not self.is_udp:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            s.bind(server_address)
            
            if not self.is_udp:
                s.listen(1)

            while True:
                print_white("waiting for new connection...")
                
                conn = None
                client_address = ["",""]
                
                if not self.is_udp:
                    while True:
                        readable, writable, errored = select([s,], [], [], 0.25)
                        if s in readable:
                            break
                        else:
                            # timeout
                            if self.detect_parent_death():
                                self.on_parent_death()
                        

                    
                    conn, client_address = s.accept()
                    self.target = client_address
                    print_white_bright("accepted client from %s:%s" % (client_address[0],client_address[1]))
                else:
                    conn = s
                    client_address == ["",""]
                    
            
                #flush stdin before real commands are inserted
                sys.stdin.flush()
            
                conn = self.prepare_socket(conn,True)
                self.sock = conn
            
                try:
                    if g_script_module:
                        self.scripter = g_script_module.PPlayScript(self)
                        self.load_scripter_defaults()          
                    
                    self.packet_loop(conn)
                except KeyboardInterrupt, e:
                    print_white_bright("\nCtrl-C: hit in client loop, exiting to accept loop. Hit Ctrl-C again to terminate.")
                    conn.close()
                except socket.error, e:
                    print_white_bright("\nConnection with %s:%s terminated: %s" % (client_address[0],client_address[1],e,))
                    if self.is_udp:
                        break

                # reset it in both cases when Ctrl-C received, or connection was closed
                self.packet_index = 0
                self.total_packet_index = 0

        except KeyboardInterrupt, e:
            print_white_bright("\nCtrl-C: bailing it out.")
            return
        except socket.error, e:
            print_white_bright("Server error: %s" % (e,))
            sys.exit(16)



    def read(self,conn):
        if have_ssl and self.use_ssl:
            data = ''
            
            while True:
                try:
                    pen = conn.pending()
                    #print_red_bright("DEBUG: %dB pending in SSL buffer" % pen)
                    if pen == 0:
                        pen = 10240
                        
                    data = conn.recv(pen)
                except ssl.SSLError as e:
                    # Ignore the SSL equivalent of EWOULDBLOCK, but re-raise other errors
                    if e.errno != ssl.SSL_ERROR_WANT_READ:
                        raise
                    continue

                except SystemError, e:
                    print_red_bright("read(): system error: %s" % (str(e),))

                data_left = conn.pending()
                while data_left:
                    data += conn.recv(data_left)
                    data_left = conn.pending()
                break
            
            self.tstamp_last_read = time.time()
            return data
        else:
            self.tstamp_last_read = time.time()
            if not self.is_udp:
                return conn.recv(24096)
            else:
                data, client_address = conn.recvfrom(24096)
                self.target = client_address
                return data

    def write(self,conn,data):
        
        if have_ssl and self.use_ssl:
            self.tstamp_last_write = time.time()
            return conn.write(data)
        else:
            self.tstamp_last_write = time.time()
            if not self.is_udp:
                return conn.send(data)
            else:
                return conn.sendto(data,self.target)

    def load_to_send(self,role,role_index):
        who = self
        if self.scripter:
            who = self.scripter
            
        to_send_idx = who.origins[role][role_index]
        return who.packets[to_send_idx]        
    

    def send_to_send(self,conn):
        
        if self.to_send:
            self.packet_index += 1
            self.total_packet_index += 1

            total_data_len = len(self.to_send)
            total_written = 0

            while total_written != total_data_len:
                cnt = self.write(conn,(str(self.to_send)))
                
                # not really clean debug, lots of data will be duplicated
                # if cnt > 200: cnt = 200
                
                data_len = len(self.to_send)

                if cnt == data_len:
                    print_green_bright("# ... %s [%d/%d]: has been sent (%d bytes)" % (str_time(),self.packet_index,len(self.origins[self.whoami]),cnt))
                else:
                    print_green_bright("# ... %s [%d/%d]: has been sent (ONLY %d/%d bytes)" % (str_time(),self.packet_index,len(self.origins[self.whoami]),cnt,data_len))
                    self.to_send = str(self.to_send)[cnt:]
                
                total_written += cnt

            self.to_send = None

    
    def detect_parent_death(self):
        # mypid = os.getpid()
        # parpid = os.getppid()
        # print_red_bright("mypid %d, parent pid %d" % (mypid,parpid,))        
        
        return os.getppid() == 1
    
    def on_parent_death(self):
        sys.exit(-2)
    

    def select_wrapper(self,conn,no_writes):
        
        inputs = [conn,sys.stdin]
        if self.nostdin:
            #print_red_bright("STDIN not used")
            inputs = [conn,]
            
        outputs = [conn]    
        if no_writes:
            outputs.remove(conn)
        
        if have_ssl and self.use_ssl:
            r = []
            w = []
            e = []
            
            if conn.pending(): r.append(conn)   # if there are bytes,
            
            if not no_writes:
                w.append(conn)                      # FIXME: we assume we can always write without select
            
            rr,ww,ee = select(inputs,outputs,[],0.2)
            if conn in rr:
                r.append(conn)
            if sys.stdin in rr:
                r.append(sys.stdin)

            if self.detect_parent_death():
                self.on_parent_death()

            return r,w,e
            
        else:

            r,w,e = select(inputs,outputs,[],0.2)
            if self.detect_parent_death():
                self.on_parent_death()
            
            
            return r,w,e

    def is_eot(self):
        return self.total_packet_index >= len(self.packets)


    def packet_read(self,conn):
        d = self.read(conn)
        
        #print_red_bright("DEBUG: read returned %d" % len(d))
        
        if not len(d):
            return len(d)

        
        # there are still some data to send/receive
        if self.total_packet_index < len(self.packets):
            # test if data are as we should expect
            aligned = False
            
            # if auto is enabled, we will not wait for user input when we received already some packet
            # user had to start pplay on the other side
            if option_auto_send:
                self.auto_send_now = time.time()
            
            # to print what we got and what we expect
            #print_white_bright(hexdump(d))
            #print_white_bright(hexdump(str(self.packets[self.total_packet_index])))

            scripter_flag = ""
            if self.scripter:
                    scripter_flag = " (sending to script)"
            
            if str(d) == str(self.packets[self.total_packet_index]):
                aligned = True
                self.total_packet_index += 1
                print_red_bright("# ... %s: received %dB OK%s" % (str_time(),len(d),scripter_flag))
            
            
            else:
                print_red_bright("# !!! /!\ DIFFERENT DATA /!\ !!!")
                smatch = difflib.SequenceMatcher(None, str(d), str(self.packets[self.total_packet_index-1]),autojunk=False)
                qr = smatch.ratio()
                if qr > 0.05:
                    print_red_bright("# !!! %s received %sB modified (%.1f%%)%s" % (str_time(),len(d),qr*100,scripter_flag))                    
                    self.total_packet_index += 1
                else:
                    print_red_bright("# !!! %s received %sB of different data%s" % (str_time(),len(d),scripter_flag))
            
            if self.scripter:
                self.scripter.after_received(self.whoami,self.packet_index,str(d))
                #print_red_bright("# received data processed")
            
            # this block is printed while in the normal packet loop (there are packets still to receive or send
            if aligned:
                if option_dump_received_correct:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")
            else:
                if option_dump_received_different:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")

        # this block means there is nothing to send/receive
        else:
            if option_dump_received_different:
                print_red_bright("#-->")
                print_red(hexdump(d))
                print_red_bright("#<--")
        
        # we have already data to send prepared!
        if self.to_send:
            #  print, but not block
            self.ask_to_send(self.to_send)
        else:
            self.ask_to_send_more()
            
        return len(d)
        

    def packet_write(self,conn,cmd_hook=False):
            
        if self.packet_index >= len(self.origins[self.whoami]):
            print_yellow_bright("# [EOT]")
            self.ask_to_send_more()
            # if we have nothing to send, remove conn from write set
            self.to_send = None
            self.write_end = True
            return
        else:
            
            if not self.to_send:
                self.to_send = self.load_to_send(self.whoami,self.packet_index)
                
        
                to_send_2 = None
                if self.scripter:
                    to_send_2 = self.scripter.before_send(self.whoami,self.packet_index,str(self.to_send))
                    if to_send_2 != None:
                        print_yellow_bright("# data modified by script!")
                        self.to_send = to_send_2
                    
                self.ask_to_send(self.to_send)
            else:
                if cmd_hook:
                    l = sys.stdin.readline()
                    
                    # readline can return empty string
                    if len(l) > 0:
                        #print_white("# --> entered: '" + l + "'")
                        self.process_command(l.strip(),'ysclxrihN',conn)

                        # in auto mode, reset current state, since we wrote into the socket
                        if option_auto_send:
                            self.auto_send_now = time.time()
                            return


                #print_white_bright("debug: autosend = " + str(option_auto_send))

                # auto_send feature
                if option_auto_send > 0 and self.send_aligned():
                    
                    now = time.time()
                    if self._last_countdown_print == 0:
                        self._last_countdown_print = now

                    delta = now - self._last_countdown_print
                    # print out the dot
                    if delta >= 1:
                        
                        self.send_countdown = round(self.auto_send_now + option_auto_send - now)
                        
                        # print dot only if there some few seconds to indicate
                        if option_auto_send >= 2:
                            #print(".",end='',file=sys.stderr)
                            #print(".",end='',file=sys.stdout)
                            if self.send_countdown > 0:
                                print("..%d" % (self.send_countdown,),end='\n',file=sys.stdout)
                                sys.stdout.flush()
                            
                        self._last_countdown_print = now                            

                    if now - self.auto_send_now >= option_auto_send:
                        
                        # indicate sending only when there are few seconds to indicate
                        if option_auto_send >= 2:
                            print_green_bright("  ... sending!")
                            
                        self.send_to_send(conn)
                        self.auto_send_now = now


    def packet_loop(self,conn):
        global option_auto_send

        running = 1        
        self.write_end = False
        self.auto_send_now = time.time()
        eof_notified = False
        
        while running:
            time.sleep(0.2)
            #print_red(".")
            
            if self.is_eot():
                
                #print_red_bright("DEBUG: is_eot returns true")
                
                if not eof_notified:
                    print_red_bright("### END OF TRANSMISSION ###")
                    eof_notified = True
                    
                if self.exitoneot:
                    #print_red_bright("DEBUG: exitoneot true")
                    
                    if self.whoami == "server":
                        if option_auto_send >= 0:
                            time.sleep(option_auto_send)
                        else:
                            time.sleep(0.5)
                    
                    if self.ssl_context:
                        #print_red_bright("DEBUG: unwrapping SSL")
                        self.sock.unwrap()
                    
                    print_red("Exiting on EOT")
                    conn.shutdown(socket.SHUT_WR)
                    conn.close()
                    sys.exit(0)
            
            r,w,e = self.select_wrapper(conn,self.write_end)
            
            #print_red_bright("DEBUG: sockets: r %s, w %s, e %s" % (str(r), str(w), str(e)))
            
            if conn in r:
                l = self.packet_read(conn)
                if l == 0:
                    print_red_bright("#--> connection closed by peer")
                    if self.exitoneot:
                        print_red("Exiting on EOT")
                        conn.shutdown(socket.SHUT_WR)
                        conn.close()
                        sys.exit(0)                        
                        
                    break    
        
            if conn in w:
                if not self.write_end:
                    self.packet_write(conn,cmd_hook=(sys.stdin in r))

            if self.write_end and sys.stdin in r:
                l = sys.stdin.readline()
                if len(l) > 0:
                    self.process_command(l.strip(),'yclxN',conn)

                if self.to_send:
                    self.ask_to_send()
                else:
                    self.ask_to_send_more()

    def cmd_replace(self,command,data):
        # something like vim's replace:  r/something/smtelse/0
        
        if len(command) > 1:
            
            parts = command.split(command[1])
            #print_yellow(str(parts))
            if len(parts) == 4:
                return re.sub(parts[1],parts[2],str(data),int(parts[3]),flags=re.MULTILINE)
            else:
                print_yellow("Syntax error: please follow this pattern:")
                print_yellow("    r<delimiter><original><delimiter><replacement><delimiter><number_of_replacements>")
                print_yellow("Example:\n    r/GET/HEAD/1 ")
                print_yellow("Note:\n    Delimiter could be any character you choose. If number_of_replacements is zero, all occurences of original string are replaced.")
                return None

        return None

    def cmd_newdata(self,command,data):
        nd = ''
        nl = 1

        print_yellow_bright("%% Enter new payload line by line (empty line commits). Lines will be sent out separated by CRLF.")
        l = sys.stdin.readline()

        while len(l) > 0:
            nd += l.strip() + "\r\n"
            nl += 1
            l = sys.stdin.readline()
                
        
        if nl > 1:
            print_yellow_bright("%% %d lines (%d bytes)" % (nl,len(nd)))
        else:
            print_yellow_bright("%% empty string - ignored")
        return nd

    def process_command(self,l,mask,conn):
        global option_auto_send
        
        #print_yellow_bright("# thank you!")
        
        if l == '':
            l = 'y'
        
        if l[0] not in mask:
            print_yellow_bright("# Unknown command in this context.")
        else:
            if (l.startswith("y")):
                self.send_to_send(conn)
                
                if self.packet_index == len(self.origins[self.whoami]):
                    print_green_bright("# %s [%d/%d]: that was our last one!!" % (str_time(),self.packet_index,len(self.origins[self.whoami])))
                
            elif l.startswith('s'):
                self.packet_index += 1                                
                self.to_send = None
                print_green_bright("# %s [%d/%d]: has been SKIPPED" % (str_time(),self.packet_index,len(self.origins[self.whoami])))

            elif l.startswith('c'):
                self.to_send = None # to reinit and ask again
                cnt = self.write(conn,"\n")
                print_green_bright("# %s custom '\\n' payload (%d bytes) inserted" % (str_time(),cnt,))

            elif l.startswith('l'):
                self.to_send = None # to reinit and ask again
                cnt = self.write(conn,"\r")
                print_green_bright("# %s custom '\\r' payload (%d bytes) inserted" % (str_time(),cnt,))

            elif l.startswith('x'):
                self.to_send = None # to reinit and ask again
                cnt = self.write(conn,"\r\n")
                print_green_bright("# %s custom '\\r\\n' payload (%d bytes) inserted" % (str_time(),cnt,))

            elif l.startswith('r') or l.startswith('N'):
                
                ret = None
                
                if l.startswith('r'):
                    ret = self.cmd_replace(l.strip(),self.to_send)
                elif l.startswith('N'):
                    ret = self.cmd_newdata(l.strip(),self.to_send)
                    
                if ret:
                    self.to_send = ret
                    print_yellow_bright("# %s custom payload created (%d bytes)" % (str_time(),len(self.to_send),))
                    self.ask_to_send(self.to_send)
                else:
                    print_yellow_bright("# Custom payload not created")

            elif l.startswith('i'):
                option_auto_send = (-1 * option_auto_send)
                if option_auto_send > 0:
                    print_yellow_bright("# Toggle automatic send: enabled, interval %d" % (option_auto_send,))
                else:
                    print_yellow_bright("# Toggle automatic send: disabled")        

            elif l.startswith('h'):
                self.print_help()
            
    def print_help(self):
        print_yellow_bright("#    More commands:");
        print_yellow_bright("#    i  - interrupt or continue auto-send feature. Interval=%d." % (abs(option_auto_send),))
        print_yellow_bright("#    r  - replace (vim 's' syntax: r/<orig>/<repl>/<count,0=all>)")
        print_yellow_bright("#       - will try to match on all buffer lines")
        print_yellow_bright("#    N  - prepare brand new data. Multiline, empty line commits. ")
        


def main():
    global option_auto_send, g_script_module, have_colorama
    


    parser = argparse.ArgumentParser(
        description=title,
        epilog=" - %s " % (copyright,))

    ds = parser.add_argument_group("Data Sources")
    group1 = ds.add_mutually_exclusive_group()
    group1.add_argument('--pcap', nargs=1, help='pcap where the traffic should be read (retransmissions not checked)')
    group1.add_argument('--smcap', nargs=1, help='textual capture taken by smithproxy')
    group1.add_argument('--script', nargs=1, help='load python script previously generated by --export command, OR use + to indicate script is embedded into source. See --pack option.')


    ac = parser.add_argument_group("Actions")
    group2 = ac.add_mutually_exclusive_group()
    group2.add_argument('--client', nargs=1, help='replay client-side of the CONNECTION, connect and send payload to specified IP address and port. Use IP:PORT or IP.')
    group2.add_argument('--server', nargs='?', help='listen on port and replay server payload, accept incoming connections. Use IP:PORT or PORT')
    
    rc = parser.add_argument_group("Remotes")
    rcgroup = rc.add_mutually_exclusive_group()
    rcgroup.add_argument('--remote-ssh', nargs=1, help='Connect to remote host with ssh, run itself (best used with `--pack`-ed script). \n    Arguments follow this IP:PORT or IP(with 22 as default SSH port)')
    
    group2.add_argument('--list', action='store_true', help='rather than act, show to us list of connections in the specified sniff file')
    group2.add_argument('--export', nargs=1, help='take capture file and export it to python script according CONNECTION parameter')
    group2.add_argument('--pack', nargs=1, help='pack packet data into the script itself. Good for automation.')
    group2.add_argument('--smprint', nargs=1,  help='print properties of the connection. Args: sip,sport,dip,dport,proto')

    ac_sniff = parser.add_argument_group("Filter on sniffer filtes (mandatory unless --script is used)")
    ac_sniff.add_argument('--connection', nargs=1, help='replay/export specified connection; use format <src_ip>:<sport>. IMPORTANT: it\'s SOURCE based to match unique flow!')


    prot = parser.add_argument_group("Protocol options")
    prot.add_argument('--ssl', required=False, action='store_true', help='toggle this flag to wrap payload to SSL (defaults to library ... default)')
    prot.add_argument('--tcp', required=False, action='store_true', help='toggle to override L3 protocol from file and send payload in TCP')
    prot.add_argument('--udp', required=False, action='store_true', help='toggle to override L3 protocol from file and send payload in UDP')
    
    prot_ssl = parser.add_argument_group("SSL protocol options")
    prot.add_argument('--ssl3', required=False, action='store_true', help='ssl3 ... won\'t be supported by library most likely')
    prot.add_argument('--tls1', required=False, action='store_true', help='use tls 1.0')
    prot.add_argument('--tls1_1', required=False, action='store_true', help='use tls 1.1')
    prot.add_argument('--tls1_2', required=False, action='store_true', help='use tls 1.2')
    
    #if ssl.HAS_TLSv1_3:
    #    prot.add_argument('--tls1_3', required=False, action='store_true', help='use tls 1.3 (library claims support)')
    
    prot_ssl = parser.add_argument_group("SSL cipher support")
    prot_ssl.add_argument('--cert', required=False, nargs=1, help='certificate (PEM format) for --server mode')
    prot_ssl.add_argument('--key', required=False, nargs=1, help='key of certificate (PEM format) for --server mode')
    
    prot_ssl.add_argument('--cipher', required=False, nargs=1, help='specify ciphers based on openssl cipher list')
    prot_ssl.add_argument('--sni', required=False, nargs=1, help='specify remote server name (SNI extension, client only)')
    prot_ssl.add_argument('--alpn', required=False, nargs=1, help='specify comma-separated next-protocols for ALPN extension (client only)')
    prot_ssl.add_argument('--ecdh_curve', required=False, nargs=1, help='specify ECDH curve name')
    
    
    var = parser.add_argument_group("Various")
    
    auto_group = var.add_mutually_exclusive_group()
    auto_group.add_argument('--noauto', required=False, action='store_true', help='toggle this to confirm each payload to be sent')
    auto_group.add_argument('--auto', nargs='?',required=False, type=float, default=5.0, help='let %(prog)s to send payload automatically each AUTO seconds (default: %(default)s)')
    
    prot.add_argument('--version', required=False, action='store_true', help='just print version and terminate')
    var.add_argument('--exitoneot', required=False, action='store_true', help='If there is nothing left to send and receive, terminate. Effective only in --client mode.')
    var.add_argument('--nostdin', required=False, action='store_true', help='Don\'t read stdin at all. Good for external scripting, applies only with --auto')
    var.add_argument('--nohex', required=False, action='store_true', help='Don\'t show hexdumps for data to be sent.')
    var.add_argument('--nocolor', required=False, action='store_true', help='Don\'t use colorama.')


    rem_ssh = parser.add_argument_group("Remote - SSH")
    rem_ssh.add_argument('--remote-ssh-user', nargs=1,  help='SSH user. You can use SSH agent, too (so avoiding this option).')
    rem_ssh.add_argument('--remote-ssh-password', nargs=1,  help='SSH password. You can use SSH agent, too (so avoiding this option).')

    args = parser.parse_args(sys.argv[1:])

    if have_colorama:
        if not args.nocolor:
            colorama.init(autoreset=False,strip=False)
        else:
            have_colorama = False

    if args.version:
        print_white_bright(title)
        print_white(copyright)
        print("",file=sys.stderr)
        print_white_bright(pplay_version)
        sys.exit(0)


    r = None
    if args.pcap:
        r = Repeater(args.pcap[0],"")
    elif args.smcap:
        r = Repeater(args.smcap[0],"")
        
    elif args.list:
        pass
    elif args.script:
        r = Repeater(None,"")
    elif args.remote_ssh:
        # the same as script, but we won't init repeater
        pass
    else:
        print_red_bright("error: no file to parse!")
        sys.exit(-1)


    if r != None:
        if args.tcp:
            r.is_udp = False

        if args.udp:
            r.is_udp = True        

        if args.ssl:
            if args.udp:
                print_red_bright("No DTLS support in python ssl wrappers, sorry.")
                sys.exit(-1)
                
            r.use_ssl = True
            
            if args.ssl3:
                r.sslv = 3
            if args.tls1:
                r.sslv = 4
            if args.tls1_1:
                r.sslv = 5
            if args.tls1_2:
                r.sslv = 6
            #if args.tls1_3:
            #    r.sslv = 7
            
            if args.cert:
                r.ssl_cert = args.cert[0]

            if args.key:
                r.ssl_key = args.key[0]
            
            
            if args.cipher:
                r.ssl_cipher = ":".join(args.cipher)
                
            if args.sni:
                r.ssl_sni = args.sni[0]
                
            if args.alpn:
                r.ssl_alpn = args.alpn[0].split(',')
                
            if args.ecdh_curve:
                r.ssl_ecdh_curve = args.ecdh_curve[0]

                
                

    if args.list:
        if args.smcap:
            r.list_smcap()
        elif args.pcap:
            r.list_pcap()
            
        sys.exit(0)

    elif args.smprint:
        if args.smcap:
            pr = None
            if args.smprint:
                pr = args.smprint[0]
                r.list_smcap(pr)
                sys.exit(0)
            
        sys.exit(-1)

    # content is controlled by script
    if args.script:
        
        try:
            
            if args.script[0] != "+":
                # add current directory into PYTHONPATH
                sys.path.append(os.getcwd())
                
                # if there is path specified in the script filename, add it to PYTHONPATH too
                if os.path.dirname(args.script[0]) != '':
                    sys.path.append(os.path.dirname(args.script[0]))
                    
                print_white_bright("Loading custom script: %s (pwd=%s)" % (args.script[0],os.getcwd()))
                
                mod_name = args.script[0]
                if mod_name.endswith(".py"):
                    mod_name = mod_name[0:-3]
                g_script_module = __import__(os.path.basename(mod_name),globals(),locals(),[],-1)

                r.scripter = g_script_module.PPlayScript(r)
                r.load_scripter_defaults()
            else:
                r.scripter = PPlayScript(r)
                r.load_scripter_defaults()
        
        except ImportError, e:
            print_red_bright("Error loading script file: %s" % (str(e),))
            #print_red(pprint.pformat(sys.))
            sys.exit(-2)
        except AttributeError, e:
            print_red_bright("Error loading script file: %s" % (str(e),))
            sys.exit(-2)

    if args.export or args.pack or args.client or args.server:
        if args.connection:
            l = args.connection[0].split(":")
            im_ip = None
            im_port = None
            
            if len(l) != 2:
                print_red_bright("error: connection syntax!")
                sys.exit(-1)

            im_ip = l[0]
            im_port = l[1]
                
            if args.smcap:
                r.read_smcap(im_ip,im_port)
            elif args.pcap:
                r.read_pcap(im_ip,im_port)
                
            if args.tcp:
                r.is_udp = False
            elif args.udp:
                r.is_udp = True
                
        
        elif args.smcap:
            # no --connection option setsockopt
            
                # okay, smcap holds only single connection
                # detect and read the connection
                
                ip_port = r.list_smcap().split(":")
                if len(ip_port) > 1:
                    im_ip = ip_port[0]
                    im_port = ip_port[1]
                    r.read_smcap(im_ip,im_port)
               
        
        # we have to have data available, unless controlled by script
        elif not args.script:
            print_white_bright("--connection argument has to be set for this option")
            sys.exit(-1)
            
            
            
            
        # cannot collide with script - those are in the exclusive argparse group
        if args.export:
            
            if args.cert:
                r.ssl_cert = args.cert[0]

            if args.key:
                r.ssl_key = args.key[0]            
            
            export_file = args.export[0]
            r.export_script(export_file)
            print_white_bright("Template python script has been exported to file %s" % (export_file,))
            sys.exit(0)

        elif args.pack:   
            pack_file = args.pack[0]
            
            if args.cert:
                r.ssl_cert = args.cert[0]

            if args.key:
                r.ssl_key = args.key[0]            
            
            r.export_self(pack_file)
            print_white_bright("Exporting self to file %s" % (pack_file,))
            sys.exit(0)


        # ok regardless data controlled by script or capture file read
        elif args.client or args.server:
            
            if args.remote_ssh:

                port = "22"
                host = "127.0.0.1"
                host_port = args.remote_ssh[0].split(":")
                
                if len(host_port) > 0:
                    host = host_port[0]
                    if not host:
                        host = "127.0.0.1"
                
                if len(args.remote_ssh) > 0:
                    port = host_port[1]
                
                print_white("remote location: %s:%s" % (host,port,))

                # this have_ is local only!
                have_script = False
                my_source = None
                try:
                    if __pplay_packed_source__:
                        print_white_bright("remote-ssh[this host] - having embedded PPlayScript")
                        have_script = True

                        # it's not greatest way to get this script source, but as long as pplay is 
                        # single-source python script, it will work. Otherwise, we will need to do quine
                        my_source = open(__file__).read()
                        
                except NameError, e:
                        have_script = False
                        #print_red_bright("!!! this source is not produced by --pack, all required files must be available on your remote!")
                    
                if not have_script:
                    import tempfile
                    print_white_bright("remote-ssh[this host] - packing to tempfile (you need all arguments for --pack)")
                        
                    if args.cert:
                        r.ssl_cert = args.cert[0]

                    if args.key:
                        r.ssl_key = args.key[0]            
                    
                    temp_file = tempfile.NamedTemporaryFile(prefix="pplay",suffix="packed")
                    r.export_self(temp_file.name)
                    print_white_bright("remote-ssh[this host] - done")
                    my_source = open(temp_file.name).read()
                    
                    have_script = True
                    
                
                if have_paramiko and my_source:


                    try:
                        paramiko.util.log_to_file('/dev/null')
                        from paramiko.ssh_exception import SSHException, AuthenticationException
                        
                        client = paramiko.SSHClient()
                        client.load_system_host_keys()
                        #client.set_missing_host_key_policy(paramiko.WarningPolicy)
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        if args.remote_ssh_user and args.remote_ssh_password:
                            client.connect(hostname=host, port=int(port), username=args.remote_ssh_user[0], password=args.remote_ssh_password[0], allow_agent=False, look_for_keys=False)
                            chan = client.get_transport().open_session(timeout=10)
                            
                        elif args.remote_ssh_user:
                            client.connect(hostname=host, port=int(port), username=args.remote_ssh_user[0])
                            chan = client.get_transport().open_session(timeout=10)
                            
                            paramiko.agent.AgentRequestHandler(chan)
                        else:
                            client.connect(hostname=host, port=int(port))
                            chan = client.get_transport().open_session(timeout=10)
                            
                            paramiko.agent.AgentRequestHandler(chan)
                            
                            
                        
                        cmd = "python -u - "
                        if have_script:
                            cmd += "--script +"

                        # iterate args and filter unwanted remote arguments, because of this we are not allowing abbreviated options :(
                        
                        filter_next = False
                        for arg in sys.argv[1:]:
                            if filter_next:
                                filter_next = False
                                continue
                            
                            if arg.startswith("--remote") or arg.startswith("--smcap") or arg.startswith("--pcap"):
                                filter_next = True
                                continue
                            
                            cmd += " " + arg
                            
                        
                        # don't monitor stdin (it's always readable over SSH)
                        # exit on the end of replay transmission --remote-ssh is intended to one-shot tests anyway
                        cmd += " --nostdin"
                        
                        # FIXME: not sure about this. Don't assume what user really wants to do
                        # cmd += " --exitoneot"
                        
                        #print_red("sending cmd: " + cmd)
                            

                        
                        #
                        #chan.set_environment_variable(name="PPLAY_COLORAMA",value="1")
                        chan.set_combine_stderr(True)
                        chan.exec_command(cmd)
                        stdin = chan.makefile("wb", 10240)
                        stdout = chan.makefile("r", 10240)
                        #stderr = chan.makefile_stderr("r", 1024)                      
                        
                        
                        # write myself (worm-like!)
                        stdin.write(my_source)
                        stdin.flush()
                        # we must shutdown, so remote python knows the script is complete
                        chan.shutdown_write()

                        
                        #print_red("remote-ssh[remote host] stdin flushed")
                        
                        while not chan.exit_status_ready():
                            time.sleep(0.1)
                            if chan.recv_ready():
                                d = chan.recv(10240)
                                if len(d) > 0:
                                    sys.stdout.write(d)

                            r,w,e = select([sys.stdin,],[],[],0.1)
                            if sys.stdin in r:
                                cmd = sys.stdin.readline()
                                
                                #print_red("cmd: " + cmd + "<<")
                                # this currently doesn't work - stdin is closed by channel                                
                                stdin.write(cmd)
    
                    
                    except paramiko.AuthenticationException, e:
                        print_red_bright("authentication failed")
                    
                    except paramiko.SSHException, e:
                        print_red_bright("ssh protocol error")
                        
                    except KeyboardInterrupt, e:
                        print_red_bright("Ctrl-C: bailing, terminating remote-ssh.")
                        

                    finally:
                        client.close()
                        
                    sys.exit(0)
                else:
                    print_red_bright("paramiko unavailable or --pack failed")
                
            
            if args.ssl:
                if not have_ssl:
                    print_red_bright("error: SSL not available!")
                    sys.exit(-1)
                
                if args.server:
                    if not args.key and not args.script:
                        print_red_bright("error: SSL server requires --key argument")
                        sys.exit(-1)
                    if not args.cert and not args.script:
                        print_red_bright("error: SSL server requires --cert argument")
                        sys.exit(-1)
                
                r.use_ssl = True

            if args.noauto:
                option_auto_send = -1
            elif args.auto:
                option_auto_send = args.auto
                
                if args.nostdin:
                    print_red_bright("stdin will be unmonitored")
                    r.nostdin = True
                
            else:
                # option_auto_send = 5
                pass
            
            
            if args.nohex:
                r.nohexdump = True
            
            
            if args.client:
                
                if len(args.client) > 0:
                    r.custom_ip = args.client[0]
                
                if args.exitoneot:
                    r.exitoneot = True
                
                r.impersonate('client')

            elif args.server:

                if args.exitoneot:
                    r.exitoneot = True

                if len(args.server) > 0:
                    # arg type is '?' so no list there, just string
                    r.custom_ip = args.server
                else:
                    r.custom_ip = None
                
                r.impersonate('server')

    else:
        print_white_bright("No-op! You wanted probably to set either --client <target_server_ip> or --server arguments ... Hmm?")

    #parser.print_help()


def cleanup():
    global g_delete_files
    for f in g_delete_files:
        try:
            print_white("unlink embedded tempfile - %s" % (f,))
            os.unlink(f)
        except OSError, e:
            pass
    
import atexit


if __name__ == "__main__":
    
    atexit.register(cleanup)
    main()
