import logging
import time
import cStringIO
from PIL import Image
from libmproxy.protocol.http import decoded
import re
import urllib # Russian messages support

class VK_user:
    def __init__(self):
        self.username = "-unknown-"
        self.id = -1
        self.known_peers = []
        self.known_hashes = []
        self.messages = []

class VK_data:
    def __init__(self):
        self.users = {}

    def from_a_check(self, string):
        pass
    
    def from_a_typing(self, string):
        m = re.match(r"act=a_typing&al=(?P<al>\d+)&gid=(?P<gid>\d+)&hash=(?P<hash>\w+)&peer=(?P<peer>\d+)", string)
        if not m:
            logging.debug("from_a_typing: Failed to parse " + string)
            return 0

        logging.debug("Typing: al = " + m.group('al') + " gid = " + m.group('gid') + 
                      " hash = " + m.group('hash') + " peer = " + m.group('peer'))
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
        return 1

    def from_a_check(self, string):
        m_key = re.match(r"act=a_check&key=[\w\W]*", string, re.UNICODE)
        m_id  = re.match(r"act=a_check&id=(?P<id>\d+)&[\w\W]*", string, re.UNICODE)

        if m_key:
            return 1

        if m_id:
            logging.debug("My id = " + m_id.group('id'))
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

        logging.debug("Unable to decode type " + m.group('type') 
                      + "! " + string)
        return 0





vk_db = VK_data()

def request(context, flow):
    try:
        with decoded(flow.request):  # automatically decode gzipped responses.
            vk_db.decode(str(flow.request.content))
    except:
        logging.debug("Exception!")

def start (context, argv):
    logging.basicConfig(filename="/root/mitm.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")

#def clientconnect(context, root_layer):
#    logging.debug("Client connect:\n")

