from charm.toolbox.pairinggroup import G1, G2, ZR, pair

class SP_MAC_EQ:

    def __init__(self, groupObject, g1Element, g2Element):
        # Create bilinary groups
        self.group = groupObject
        self.g1 = g1Element
        self.g2 = g2Element
        
    def keyGen(self, length):

        # Create secret key from random uniformly distributed elements from modular subspace
        secretKey = [self.group.random(ZR) for _ in range(length)]
        
        return secretKey

    def createMac(self, secretKey, rawMessage, randomScalar):

        # the raw message string, is hashed via the group hash to introduce randomness, 
        # The hash is implicity matched to an element in G1 via charm algorithm.
        encodedMessages = [self.group.hash(message, G1) for message in rawMessage]

        # Compute the wheighted sum (sum_i x_i * M_i)
        wheightedSum = self.computeWheightedSum(secretKey, encodedMessages)


        # compute the inverse via the group order 
        modularScalarInverse = randomScalar ** -1

        # create the two tags
        tagR = wheightedSum * randomScalar
        tagT = self.g2 * modularScalarInverse

        return encodedMessages, tagR, tagT

    def verify(self, secretKey, encodedMessages, tagR, tagT):

        verify = False

        # Compute the wheighted sum (sum_i x_i * M_i)
        wheightedSum = self.computeWheightedSum(secretKey, encodedMessages)   
        
        # Cancel out the random scalar of the computed tags and given tags.
        left = pair(wheightedSum, self.g2)
        right = pair(tagR, tagT)

        # If the computed tags then match the given tags, verification succesfull
        if left == right:
            verify = True
    
        return verify

    def changeRepresentation(self, encodedMessages, tagR, tagT, modularScalarMu):

        randomScalar = self.group.random(ZR)

        # Change the encoded messages to the mu representation of the encoding
        changedMessages = [message * modularScalarMu for message in encodedMessages] 

        # randomize using the scalar and Mu to match the changed messages
        newTagR = tagR * (randomScalar * modularScalarMu)
        newTagT = tagT * (randomScalar ** -1)

        # return new representation
        return changedMessages, newTagR, newTagT

    def computeWheightedSum(self, secretKey, encodedMessages):

        # get the base element in G1
        baseElement = self.group.init(G1, 1) 
        wheightedSum = baseElement

        # for each message check that it's not the base element, if not,
        # sum up all the encoded messages with correspnding secretKey
        for i in range(0, len(secretKey)):
            if encodedMessages[i] == baseElement:
                break
            wheightedSum +=  encodedMessages[i] * secretKey[i]

        return wheightedSum