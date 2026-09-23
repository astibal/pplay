import datetime

class PPlayScript:

    def __init__(self, pplay, args=None):
        # access to pplay engine
        self.pplay = pplay

        self.packets = []
        self.packets.append(b'C1\r\n')
        self.packets.append(b'S1\r\n')
        self.packets.append(b'C2\r\n')
        self.packets.append(b'S2\r\n')

        self.origins = {}

        self.server_port = 80
        self.custom_sport = None
        self.origins['client']=[0,2]
        self.origins['server']=[1,3]
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None



    def before_send(self,role,index,data):
        # when None returned, no changes will be applied and packets[ origins[role][index] ] will be used
        if role == 'server' and index == 1:
            return self.pplay.to_send + (" %s" % datetime.datetime.now()).encode("utf-8")

        return None

    def after_received(self,role,index,data):
        # return value is ignored: use it as data gathering for further processing
        return None
