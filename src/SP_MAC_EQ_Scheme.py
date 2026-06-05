from charm.toolbox.pairinggroup import G1, ZR, pair


class SP_MAC_EQ:

    def __init__(self, groupObject, g1Element, g2Element):

        self.group = groupObject
        self.g1 = g1Element
        self.g2 = g2Element


    def keyGen(self, length):

        secretKey = []

        for _ in range(length):
            scalar = self.group.random(ZR)
            while scalar == self.group.init(ZR):
                scalar = self.group.random(ZR)
            secretKey.append(scalar)

        return secretKey

    def createMac(self, secretKey, encodedMessageVector, randomScalarA):

        # Compute the hidden linear combination sum_i x_i * M_i.
        weightedSum = self.computeWeightedSum(secretKey, encodedMessageVector)

        # Compute a^{-1}. This is needed for the second tag component tagT: T = a^{-1} * G2.
        randomScalarAInverse = randomScalarA ** -1

        # Create the two tags:
        # tagR: R = a * (sum_i x_i M_i)
        # tagT: T = a^{-1} * G2
        tagR = weightedSum * randomScalarA
        tagT = self.g2 * randomScalarAInverse

        return tagR, tagT


    def verify(self, secretKey, encodedMessageVector, tagR, tagT):

        # Compute the weighted sum (sum_i x_i * M_i)
        weightedSum = self.computeWeightedSum(secretKey, encodedMessageVector)

        # Check that no message M_i = 0_G1
        if weightedSum is None:
            return False

        # Cancel out the random scalar of the computed tags and given tags using pair() from Charm:
        # e(a * (sum_i x_i M_i), a^{-1} * G2)
        left = pair(weightedSum, self.g2)
        right = pair(tagR, tagT)

        # If the computed tags match the given tags, verification is successful.
        return left == right


    def changeRepresentation(self, encodedMessageVector, tagR, tagT, randomScalarMu):

        # Get random scalar ζ and ensuring ζ = Z_p*
        randomScalar = self.group.random(ZR)
        while randomScalar == self.group.init(ZR):
                randomScalar = self.group.random(ZR)

        # Change the encoded message vector to the mu representation
        changedMessageVector = [message * randomScalarMu for message in encodedMessageVector]

        # Randomize using the scalar and mu to match the changed messages while preserving distribution
        newTagR = tagR * (randomScalar * randomScalarMu)
        newTagT = tagT * (randomScalar ** -1)

        # Return new representation
        return changedMessageVector, newTagR, newTagT


    def computeWeightedSum(self, secretKey, encodedMessageVector):

        # Get the base element in G1
        baseElement = self.group.init(G1)
        weightedSum = baseElement

        # Create linear combination sum_i x_i M_i.
        # For each message, check that it is not the base element (M_i = 0_G1). If yes, return None.
        for i in range(len(secretKey)):
            if encodedMessageVector[i] == baseElement:
                return None
            weightedSum += encodedMessageVector[i] * secretKey[i]

        return weightedSum