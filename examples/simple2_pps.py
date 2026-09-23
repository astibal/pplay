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
        self.origins['client'] = [0, 2]
        self.origins['server'] = [1, 3]
        self.ssl_cert = None
        self.ssl_key = None
        self.ssl_ca_cert = None
        self.ssl_ca_key = None

        self.last_recv = b""

    def before_send(self, role, index, data):
        # when None returned, no changes will be applied and packets[ origins[role][index] ] will be used

        return None

    def after_received(self, role, index, data):
        # return value is ignored: use it as data gathering for further processing

        if role == "server":
            print ("Thanks for '%s' @ %d!" % (str(data), index))
            self.last_recv += (" " + str(data)).encode("utf-8")

            if self.pplay.to_send:
                self.pplay.to_send += self.last_recv
            else:
                self.pplay.to_send = self.last_recv
            # self.pplay.ask_to_send()

        return None
