from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from SP_MAC_EQ_Scheme import SP_MAC_EQ

group = PairingGroup('SS512')
schemeConstruct = SP_MAC_EQ(group)

attributes = ["18", "Danish", "Plumber"]
length = len(attributes)

secretKey = schemeConstruct.keyGen(length)
encodedMessages, tagR, tagT = schemeConstruct.createMac(secretKey, attributes)   

print("SecretKey: ", secretKey)
print("Message: ", attributes)
print("tagR: ", tagR)
print("tagT:", tagR)

print("Verify inital tags: ", schemeConstruct.verify(secretKey, encodedMessages, tagR, tagT))

randomMu = group.random(ZR)
changedMessages, newTagR, newTagT = schemeConstruct.changeRepresentation(encodedMessages, tagR, tagT, randomMu)

print("ChangedMessages: ", changedMessages)
print("newTagR: ", newTagR)
print("newTagT: ", newTagT)


print("Verify rerandomized tags:", schemeConstruct.verify(secretKey, changedMessages, newTagR, newTagT))

