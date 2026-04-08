from charm.toolbox.pairinggroup import G1, ZR

class KVAC_GGM:

    def __init__(self, groupObject):

        self.group = groupObject
        self.G = self.group.random(G1)

    def keyGen(self):

        generator = self.G

        x = self.group.random(ZR)
        v = self.group.random(ZR)
        r = self.group.random(ZR)

        secretKey = x, v
        publicIssuerParameter = r * generator, r * x * generator, v * generator

        return secretKey, publicIssuerParameter