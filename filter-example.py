import logging
import time
import cStringIO
from PIL import Image
from libmproxy.protocol.http import decoded

def request(context, flow):
    try:
        logging.debug("request")
        with decoded(flow.request):  # automatically decode gzipped responses.
            logging.debug("new: ")
            s = cStringIO.StringIO(flow.request.content)
            logging.debug("haha " + str(s.getvalue()))
    except:
        logging.debug("CHECK CODE, IDIOT!!!!!!!!!!!")

def start (context, argv):
    logging.basicConfig(filename="/root/workspace/mitm/log.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")

def clientconnect(context, root_layer):
    logging.debug("Client connect:\n")

