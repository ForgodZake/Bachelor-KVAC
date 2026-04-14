from charm.toolbox.pairinggroup import G1, ZR
from PolyCommmitBase import PolyCommitBase

class DVSC(PolyCommitBase):

    def __init__(self, groupObject, g1Element, gPrimeElement):
        
        super().__init__(groupObject, g1Element)
        self.gPrime = gPrimeElement

    def buildCommitmentBasis(self, secretKey, upperBound):

        basisElement = self.g1
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
        disclosedAttributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]

        # Get polynomial coefficients
        coefficients = self.createPolynomial(disclosedAttributes)

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

        return commitment, self.gPrime

    def randomize(self, commitment1, commitment2, randomScalarMu):

        newCommitment1 = commitment1 * randomScalarMu
        newCommitment2 = commitment2 * randomScalarMu

        return newCommitment1, newCommitment2

    def verifySubset(self, secretKey, randomizedCommitment, witness, requiredAttributeSubsetRaw):

        # Hash the disclosed attributes and build the subset polynomial f_D(X)
        disclosedAttributeSubset = [self.group.hash(attribute, ZR) for attribute in requiredAttributeSubsetRaw]
        coefficients = self.createPolynomial(disclosedAttributeSubset)
    
        # Evaluate f_D at the secret key v and combine it with the witness
        # to reconstruct the commitment value that should match C'
        polynomialAtSecret = self.evaluatePolynomial(coefficients, secretKey)
        commitment = polynomialAtSecret * witness

        # Check that the reconstructed commitment value matches the randomized commitment
        return True if randomizedCommitment == commitment else False