from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from SP_MAC_EQ_Scheme import SP_MAC_EQ

group = PairingGroup('SS512')
schemeConstruct = SP_MAC_EQ(group)

M = ["Hello1", "Hello2", "Hello3"]
length = len(M)

secretKey = schemeConstruct.keyGen(length)
(tag1, tag2) = schemeConstruct.createMac(secretKey, M)   

print("tag1: ", tag1)
print("tag2:", tag2)

