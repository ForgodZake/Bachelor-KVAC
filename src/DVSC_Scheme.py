from charm.toolbox.pairinggroup import ZR
from Common_DVSC_Functions import Common_DVSC_Functions

class DVSC(Common_DVSC_Functions):

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


    def buildSigmaAnnouncement(self, randomScalar, commitmentBasis):
        
        # creates the announcement sequence by upscaling each element from the prior by the random scalar
        announcementSequence = []
        for i in range(len(commitmentBasis)):
            announcementI = commitmentBasis[i] * randomScalar
            announcementSequence.append(announcementI)

        return announcementSequence


    def keyGen(self, upperBound):

        secretKey = self.group.random(ZR)
        while secretKey == self.group.init(ZR):
                secretKey = self.group.random(ZR)
        commitmentBasis = self.buildCommitmentBasis(secretKey, upperBound)

        randomScalar = self.group.random(ZR)
        announcement = self.buildSigmaAnnouncement(randomScalar, commitmentBasis[:-1])
        challenge = self.hashForChallenge((announcement, commitmentBasis))
        response = randomScalar + challenge * secretKey

        return secretKey, challenge, response, commitmentBasis
    

    def verifyIssuerParameter(self, challenge, response, commitmentBasis):

        proposedChallenge = []
        sigmaOutPut = self.buildSigmaAnnouncement(response, commitmentBasis[:-1])

        # Compute the proposed challenge 
        for i in range(len(commitmentBasis) - 1):
            proposedChallenge.append(sigmaOutPut[i] - (challenge * commitmentBasis[i + 1]))

        challengeCheck = self.hashForChallenge((proposedChallenge, commitmentBasis))

        return challengeCheck == challenge
        

    def commit(self, commitmentBasis, disclosedAttributes):

        # Get polynomial coefficients
        coefficients = self.createPolynomial(disclosedAttributes)
        
        # Create and return commitment
        commitment = self.createCommitment(coefficients, commitmentBasis)

        return commitment, self.gPrime


    def randomize(self, commitment1, commitment2, randomScalarMu, upk, gPrime):

        """
        Extension:
        - Randomizes both the DVSC commitment and the user public key material.
        - Uses the same μ for C_1, C_2, upk, and G'.
        
        Reason: Keeps the randomized commitment and randomized public key in the same presentation representation,
        which is required for the later non-transferability proof.
        """

        newCommitment1 = commitment1 * randomScalarMu
        newCommitment2 = commitment2 * randomScalarMu
        newUpk = upk * randomScalarMu
        newGPrime = gPrime * randomScalarMu

        return newCommitment1, newCommitment2, newUpk, newGPrime


    def verifySubset(self, secretKey, randomizedCommitment, witness, disclosedAttributeSubset):

        # Evaluate f_D at the secret key v and combine it with the witness
        # to reconstruct the commitment value that should match C'
        polynomialAtSecret = self.evaluatePolynomial(disclosedAttributeSubset, secretKey)
        commitment = polynomialAtSecret * witness

        # Check that the reconstructed commitment value matches the randomized commitment
        return randomizedCommitment == commitment