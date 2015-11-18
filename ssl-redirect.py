import logging
import time
from libmproxy.protocol.http import decoded
import re
from libmproxy.protocol.http import HTTPResponse
from netlib.odict import ODictCaseless

class client_status_handler:
    def __init__ (self):
        self.db_file_name = 'cert-db.dat'

    def get_db (self):
        cert_db_file = open(self.db_file_name, 'r')
        cert_db = cert_db_file.readlines()
        cert_db_file.close()
        return cert_db

    def add_to_db (self, client_ip):
        with open(self.db_file_name, 'a') as cert_db_file:
            cert_db_file.write(client_ip + " no\n")

    def change_status (self, client_ip, status):
        cert_db = self.get_db()
        cert_db_file = open(self.db_file_name, 'w')
        for i in range(len(cert_db)):
            if (((cert_db[i]).split())[0] == client_ip):
                cert_db_file.write(cert_db[i][:-3] + status + "\n")
            else:
                cert_db_file.write(cert_db[i])

    def check_status (self, client_ip):
        cert_db = self.get_db()
        status = "no"
        for i in range(len(cert_db)):
            if (((cert_db[i]).split())[0] == client_ip):
                status = ((cert_db[i]).split())[1]
                return status
        self.add_to_db(client_ip)
        return status

#=============================================
csh = client_status_handler()
 
def response(context, flow):
    try:
        logging.debug("response")
        logging.debug(flow.server_conn.ssl_established)
        logging.debug(flow.request.scheme)
        client_status = csh.check_status(str(flow.client_conn.address).split("'")[1])
        skip = flow.request.host == "185.31.17.133"
#        skip = skip or flow.request.host == "81.5.81.98"
        logging.debug(flow.request.host)
        if (not skip and client_status == "dl" and not flow.server_conn.ssl_established):
#            logging.debug("replay")
#            logging.debug(flow.request.pretty_host(hostheader=True))
#            context.kill_flow(flow)
            logging.debug("replay")
            with open("cert.txt", "r") as cert_file:
                cert_str = cert_file.read()
	    resp = HTTPResponse([1, 1], 200, "OK", ODictCaseless([["Content-Type", "text/html"]]), cert_str)
            flow.reply(resp)
#        csh.change_status(str(flow.client_conn.address).split("'")[1], "dl")
#            f = context.duplicate_flow(flow)
#            f.request.host = "infosec-216.github.io"
#            f.request.update_host_header()
#            context.replay_request(f)
#        else:
#            csh.change_status(str(flow.client_conn.address).split("'")[1], "in")

#            with decoded(flow.response):
#                if ('text/html' in flow.response.headers["content-type"][0]):
#	            flow.response.headers["content-type"] = ["text/html; charset=uft-8"]
#                    with open("cert.txt", "r") as cert_file:
#                        cert_str = cert_file.read()
#                    flow.response.content = cert_str
#                    csh.change_status(str(flow.client_conn.address).split("'")[1], "dl")
#        if (client_status == "dl"):
#            with decoded(flow.response):
#                if ('text/html' in flow.response.headers["content-type"][0]):
#                    flow.response.headers["content-type"] = ["text/html; charset=uft-8"]
#                    with open("hello-html.txt", "r") as cert_file:
#                        cert_str = cert_file.read()
#                    flow.response.content = cert_str
#                    csh.change_status(str(flow.client_conn.address).split("'")[1], "in")
        logging.debug("=======================================================")
    except Exception as e:
        logging.debug("CHECK CODE, IDIOT!!!!!!!!!!!")
        logging.debug(type(e))
        logging.debug(e)

def request(context, flow):
    try:
        logging.debug("request")
        logging.debug(flow.request.host)
        client_status = csh.check_status(str(flow.client_conn.address).split("'")[1])
        skip = flow.request.host == "185.31.17.133"
        if (not skip and not flow.server_conn.ssl_established):
            with open("cert.txt", "r") as cert_file:
                cert_str = cert_file.read()
            resp = HTTPResponse([1, 1], 200, "OK", ODictCaseless([["Content-Type", "text/html"]]), cert_str)
            flow.reply(resp)
#            flow.request.host = "infosec-216.github.io"
#            flow.request.update_host_header()
#            csh.change_status(str(flow.client_conn.address).split("'")[1], "dl")
        logging.debug(flow.server_conn.ssl_established)
    except Exception as e:
        logging.debug("CHECK CODE, IDIOT!!!!!!!!!!!")
        logging.debug(type(e))
        logging.debug(e)


def start (context, argv):
    logging.basicConfig(filename="/root/workspace/mitm/log.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
