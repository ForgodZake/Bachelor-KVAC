from charm.toolbox.pairinggroup import G2, ZR, pair
from charm.toolbox.sigmaprotocol import Sigma 
class DVSC(Sigma):

    def __init__(self, groupObject):
        Sigma.__init__(self, groupObject, None)


    def keyGen(self, upperBound):


        secretKey = self.group.random(ZR)


        return 1

    def commit():
        return 1

    def randomize():
        return 1

    def openSubset():
        return 1

    def verifySubset():
        return 1 
