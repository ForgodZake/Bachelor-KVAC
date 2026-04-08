from charm.toolbox.pairinggroup import G1, G2, ZR, PairingGroup
from DVSC_Scheme import DVSC
from SP_MAC_EQ_Scheme import SP_MAC_EQ



class KVAC_MEQ:

    def __init__(self, groupObject):
        
        self.group = groupObject
        self.G1 = self.group.random(G1)
        self.G2 = self.group.random(G2)

        self.Scheme_DVSC = DVSC(self.group)
        self.Scheme_MEQ = SP_MAC_EQ(self.group)

