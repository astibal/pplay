__pplay_packed_source__ = True


def readfile(fnm):
    return open(fnm).read()


class PPlayScript:

    def __init__(self, pplay, args=None):
        # access to pplay engine
        self.pplay = pplay

        self.packets = []
        self.args = args
        self.origins = {}

        print("pplayscript: %s" % self.args)

        self.packets = [b'200 PPlay SMTP Server\r\n',
                        b'EHLO A\r\n',
                        b'200 PPlay SMTP Server - nice to see you.\r\n',
                        b'STARTTLS\r\n',
                        b'200 ready to start TLS\r\n',
                        b'EHLO A\r\n',
                        b'200 PPlay SMTP Server\r\n',
                        b'MAIL FROM: a@b.c\r\n',
                        b'200 Go ahead\r\n',
                        b'MAIL TO: someone@here.local\r\n',
                        b'200 Go ahead\r\n',
                        b'DATA\r\n',
                        b'200 Go ahead\r\n',
                        b'Subject: is anybody out there\r\n',
                        b'\r\n\r\n.\n']

        self.server_port = 0
        self.custom_sport = None
        self.origins['client'] = [1, 3, 5, 7, 9, 11, 13, 14]
        self.origins['server'] = [0, 2, 4, 6, 8, 10, 12]
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None

    def after_send(self, role, index, data):

        # Some debugging outputs
        # print(">>> role:" + str(role) + " index:" + str(index))
        # print(">>> after send: " + str(data))

        if role == 'server':
            if index == 2:
                print(">>> server side starttls ")
                self.pplay.starttls()
            else:
                pass
                # time.sleep(2)

    def before_send(self, role, index, data):

        # Some debugging outputs
        # print(">>> role:" + str(role) + " index:" + str(index))
        # print(">>> before send: " + str(data))

        if index == 2 and role == 'client':
            print(">>> client side starttls ")
            self.pplay.starttls()
