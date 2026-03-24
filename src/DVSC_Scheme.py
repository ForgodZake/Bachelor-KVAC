from charm.toolbox.pairinggroup import G1, ZR, pair

class DVSC:

    def __init__(self, groupObject):
        self.group = groupObject


    from charm.toolbox.pairinggroup import G1, ZR, pair

class DVSC:

    def __init__(self, groupObject):
        self.group = groupObject

    def buildCommitmentBasis(self, secretKey, upperBound):

        basisElement = self.group.random(G1)
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey
            commitmentBasis.append(basisElement)

        return commitmentBasis

    def hashForChallenge(self, announcementSequence, commitmentBasis):
        data = b""
        for announcementElement in announcementSequence:
            data += self.group.serialize(announcementElement)
        for basisElement in commitmentBasis:
            data += self.group.serialize(basisElement)
        return self.group.hash(data, ZR)

    def sigmaProtocol(self, randomScalar, commitmentBasis):

        sigmaSequence = []
        for i in range(len(commitmentBasis)):
            sigma_i = commitmentBasis[i] * randomScalar
            sigmaSequence.append(sigma_i)
        return sigmaSequence
    
    def createPolynomial(self, attributes):
        
        coefficients = [1]

        for attribute in attributes:
            newCoefficients = [self.group.init(ZR, 0)] * (len(coefficients) + 1)

            for i in range(len(coefficients)):
                newCoefficients[i] += -attribute * coefficients[i]
                newCoefficients[i + 1] += coefficients[i]

            coefficients = newCoefficients

        return coefficients

    def createCommitment(self, coefficients, commitmentBasis):

        commitment = self.group.init(G1, 1)

        for i in range(len(coefficients)):
            commitment += coefficients[i] * commitmentBasis[i]

        return commitment

    def keyGen(self, upperBound):

        secretKey = self.group.random(ZR)
        commitmentBasis = self.buildCommitmentBasis(secretKey, upperBound)

        randomScalar = self.group.random(ZR)
        announcement = self.sigmaProtocol(randomScalar, commitmentBasis[:-1])
        challenge = self.hashForChallenge(announcement, commitmentBasis)
        response = randomScalar + challenge * secretKey

        return secretKey, challenge, response, commitmentBasis

    def commit(self, challenge, response, commitmentBasis, attributesRaw):

        # Hash attributes to ZR space
        attributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]

        # Get polynomial coefficients
        coefficients = self.createPolynomial(attributes)

        proposedChallenge = []
        sigmaOutPut = self.sigmaProtocol(response, commitmentBasis[:-1])

        # Compute the proposed challenge 
        for i in range(len(commitmentBasis) - 1):
            proposedChallenge.append(sigmaOutPut[i] - (challenge * commitmentBasis[i + 1]))

        challengeCheck = self.hashForChallenge(proposedChallenge, commitmentBasis)

        # Checks if proposed challenge is valid
        if challengeCheck != challenge:
            return None
        
        # Create and return commitment
        commitment = self.createCommitment(coefficients, commitmentBasis)   
        randomScalarG1 = self.group.random(G1)

        return commitment, randomScalarG1

    def randomize(self, commitment, randomScalarG1, randomScalarMu):

        # randomice commitment with given scalar
        newCommitment = commitment * randomScalarMu
        newRandomScalarG1 = randomScalarG1 * randomScalarMu

        return newCommitment, newRandomScalarG1

    def openSubset(self, commitmentBasis, attributes, attributeSubset, randomScalarMu):

        remainingAttributesRaw = []
        # Create the set without the subset (S / D)
        for i in range(len(attributes)):
            if not (attributes[i] in attributeSubset):
                remainingAttributesRaw.append(attributes[i])

        remainingAttributes = [self.group.hash(attributeRaw, ZR) for attributeRaw in remainingAttributesRaw]

        coefficients = self.createPolynomial(remainingAttributes)

        witness = randomScalarMu * self.createCommitment(coefficients, commitmentBasis)

        return witness

    def verifySubset(self, secretKey, randomizedCommitment, witness, attributeSubsetRaw):

        attributesSubset = [self.group.hash(attribute, ZR) for attribute in attributeSubsetRaw]

        coefficients = self.createPolynomial(attributesSubset)
        subsetEvaluation = self.evaluatePolynomial(coefficients, secretKey)
        commitment = subsetEvaluation * witness

        print("randomizedCommitment: ", randomizedCommitment)
        print("commmitment: ", commitment)

        if randomizedCommitment == commitment:
            return True
        
        return False
    
    def evaluatePolynomial(self, coefficients, x):
        result = self.group.init(ZR, 0)
        power = self.group.init(ZR, 1)

        for coefficient in coefficients:
            result += coefficient * power
            power *= x

        return result