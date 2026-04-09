from charm.toolbox.pairinggroup import G1, ZR

class DVSC:

    def __init__(self, groupObject):
        self.group = groupObject
        self.G = self.group.random(G1)
        self.GPrime = self.group.random(G1)

    def buildCommitmentBasis(self, secretKey, upperBound):

        basisElement = self.G
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey
            commitmentBasis.append(basisElement)
        #return commitment basis
        return commitmentBasis

    def hashForChallenge(self, announcementSequence, commitmentBasis):

        # creates a combined hash of announementSequence and commitmentBasis,
        # using a serialized byte representasion
        byteRepresentation = b""
        for announcementElement in announcementSequence:
            byteRepresentation += self.group.serialize(announcementElement)
        for basisElement in commitmentBasis:
            byteRepresentation += self.group.serialize(basisElement)
        return self.group.hash(byteRepresentation, ZR)

    def sigmaProtocol(self, randomScalar, commitmentBasis):
        
        # creates the sigma sequence by upscaling each element from the prior by the random scalar
        sigmaSequence = []
        for i in range(len(commitmentBasis)):
            sigmaI = commitmentBasis[i] * randomScalar
            sigmaSequence.append(sigmaI)

        return sigmaSequence
    
    def createPolynomial(self, attributes):
        
        coefficients = [1]

        # for each attribute we update the polynomial degree,
        # by doing currentPoly * (X - a)
        for attribute in attributes:
            # Set the length of the next degree poly
            newCoefficients = [0] * (len(coefficients) + 1)
            
            # Update all the coefficients by currentPoly * (X - a)
            for i in range(len(coefficients)):
                newCoefficients[i] += -attribute * coefficients[i]
                newCoefficients[i + 1] += coefficients[i]

            # store and repeat
            coefficients = newCoefficients

        return coefficients

    def createCommitment(self, coefficients, commitmentBasis):

        commitment = self.group.init(G1, 1)

        # create commitment by scaing each basis element by the coefficient (f_i * V_i)
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

        return commitment, self.GPrime

    def randomize(self, commitment1, commitment2, randomScalarMu):

        newCommitment1 = commitment1 * randomScalarMu
        newCommitment2 = commitment2 * randomScalarMu

        return newCommitment1, newCommitment2

    def openSubset(self, commitmentBasis, attributes, attributeSubset, randomScalarMu):

        remainingAttributesRaw = []
        # Create the set without the subset (S / D)
        for i in range(len(attributes)):
            if not (attributes[i] in attributeSubset):
                remainingAttributesRaw.append(attributes[i])

        # Hash the remaining attributes (needed as they are strings) and create the polynomial
        remainingAttributes = [self.group.hash(attributeRaw, ZR) for attributeRaw in remainingAttributesRaw]
        coefficients = self.createPolynomial(remainingAttributes)

        # Create the witness by scaling the commitment with our random mu
        witness = randomScalarMu * self.createCommitment(coefficients, commitmentBasis)

        return witness

    def verifySubset(self, secretKey, randomizedCommitment, witness, requiredAttributeSubsetRaw):

        # Hash the disclosed attributes and build the subset polynomial f_D(X)
        attributesSubset = [self.group.hash(attribute, ZR) for attribute in requiredAttributeSubsetRaw]
        coefficients = self.createPolynomial(attributesSubset)
    
        # Evaluate f_D at the secret key v and combine it with the witness
        # to reconstruct the commitment value that should match C'
        polynomialAtSecret = self.evaluatePolynomial(coefficients, secretKey)
        commitment = polynomialAtSecret * witness

        # Check that the reconstructed commitment value matches the randomized commitment
        return True if randomizedCommitment == commitment else False
    
    def evaluatePolynomial(self, coefficients, secretKey):
        
        result = self.group.init(ZR, 0)
        power = 1

        # compute the output of the polynomial with secretKey as input 
        for coefficient in coefficients:
            result += coefficient * power
            power *= secretKey

        return result