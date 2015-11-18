import logging
import time
from libmproxy.protocol.http import decoded
import re
from libmproxy.protocol.http import HTTPResponse
from netlib.odict import ODictCaseless

def request(context, flow):
    try:
        skip = flow.request.host == "185.31.17.133"
        if (not skip and not flow.server_conn.ssl_established):
            with open("cert.txt", "r") as cert_file:
                cert_str = cert_file.read()
            resp = HTTPResponse([1, 1], 200, "OK", ODictCaseless([["Content-Type", "text/html"]]), cert_str)
            flow.reply(resp)
    except Exception as e:
        logging.debug("CHECK CODE, IDIOT!!!!!!!!!!!")
        logging.debug(type(e))
        logging.debug(e)


def start (context, argv):
    logging.basicConfig(filename="/root/workspace/mitm/log.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
