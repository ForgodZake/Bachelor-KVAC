from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair

class SP_MAC_EQ:

    def __init__(self, groubGenerator):
        
        self.group = groubGenerator
        self.setup()


    def setup(self):
        # Create bilinary groups
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

    def keyGen(self, length):

        # Create secret key from random uniformly distributed elements from modular subspace
        secretKey = [self.group.random(ZR) for _ in range(length)]
        
        return secretKey

    def createMac(self, secretKey, rawMessage):

        R = self.group.init(G1, 1)
        Message = [self.group.hash(m, G1) for m in rawMessage]

        for i in range(1, len(secretKey)):

            R *=  Message[i] ** secretKey[i]

        # get a random element from the prime modular group as scalar
        modularScalar = self.group.random(ZR)
        # compute the inverse via the group order 
        modularScalarInverse = modularScalar ** -1

        # create the two tags
        tag1 = R ** modularScalar
        tag2 = self.g2 ** modularScalarInverse

        return (tag1, tag2)

    def verify(secretKey, Message, tag):
        return 0 

    def changeRepresentation(tag, modularScalar):
        return 0