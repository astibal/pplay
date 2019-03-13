class PPlayScript:

    def __init__(self, pplay):
        # access to pplay engine
        self.pplay = pplay

        self.packets = []
        self.packets.append('C1\r\n')
        self.packets.append('S1\r\n')
        self.packets.append('C2\r\n')
        self.packets.append('S2\r\n')

        self.origins = {}

        self.server_port = 80
        self.origins['client'] = [0, 2]
        self.origins['server'] = [1, 3]

        self.last_recv = ""

    def before_send(self, role, index, data):
        # when None returned, no changes will be applied and packets[ origins[role][index] ] will be used

        return None

    def after_received(self, role, index, data):
        # return value is ignored: use it as data gathering for further processing

        if role == "server":
            print ("Thanks for '%s' @ %d!" % (str(data), index))
            self.last_recv += (" " + str(data))

            if self.pplay.to_send:
                self.pplay.to_send += self.last_recv
            else:
                self.pplay.to_send = self.last_recv
            # self.pplay.ask_to_send()

        return None
