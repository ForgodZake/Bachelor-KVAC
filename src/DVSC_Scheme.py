from charm.toolbox.pairinggroup import ZR
from Common_DVSC_Functions import Common_DVSC_Functions

class DVSC(Common_DVSC_Functions):

    """
    Implementation of the Designated-Verifier Set Commitment scheme (DVSC).
    This is described in section four of Keyed-Verification Anonymous Credentials
    with Highly Efficient Partial Disclosure.

    Notation in paper and our correlating naming scheme:
    - secretKey: sk = v where v ∈ Z_p*.
    - commitmentBasis: (V_0, ..., V_t) where V_j = v^j * G.
    - gPrime: is the random generator from G1 denoted G'.
    - challenge, response: corresponds to the Fiat-Shamir style proof of knowledge π used to show knowledge of v behind the basis.
    - attributesRaw: the set S before hashing, represented in our implementation as raw attributes.
    - requiredAttributeSubsetRaw: the subset D ⊆ S before hashing.
    - commitment: C = (f_S(v)G, G').
    - randomizedCommitment: C' = (μf_S(v)G, μG').
    - witness: W = μf_{S\D}(v)G.
    - randomScalarMu: μ ∈ Z_p*.
    
    Implementation note:
    !!!!!!!!!!!!!! Wanna change to not include hashes in functions !!!!!!!!!!!!
    
    """

    def __init__(self, groupObject, g1Element, gPrimeElement):

        """
        The initialization consists of storing the G' fixed generator and the group context used in the scheme.
        This is done as part of super class structure Common_DVSC_Functions,
        which is used for initializing both DVSC and KVAC_GGM.

        Used by:
        The Issuer will initialize the DVSC scheme object.

        Notation in paper and our correlating naming scheme:
        - groupObject: The bilinear group of type-3 noted BG, which is returned by MEQ.SetupR(1^λ).
        - g1Element, gPrimeElement: The two generators from G1.
        
        Why we do this:
        DVSC does not operate using pairing groups, but uses element from G1 as DVSC is initialized and used through KVAC_MEQ. 
        The DVSC Scheme keeps the two elements from G1,
        as the commitment and randomized commitment uses a pair of group elements to accomadate KVAC_MEQ requirements.
        The commitment and randomized commitment are defined as:
        C = (f_S(v)G, G') and C' = (μf_S(v)G, μG').
        
        """

        super().__init__(groupObject, g1Element)
        self.gPrime = gPrimeElement


    def buildCommitmentBasis(self, secretKey, upperBound):
        
        """
        Build the public commitment basis (V_0, ..., V_t), where V_j = v^j * G.

        Used by:
        The issuer initially uses this method through keyGen()
        The resulting commitmentBasis is later used by issuer and user when computing commitments and subset openings.

        Notation in paper and our correlating naming scheme:
        - secretKey: sk = v where v ∈ Z_p*.
        - upperBound: 
        
        Why we do this:
        verifyIssuerParameter() is a helper function used when generating the key in keyGen().
        The commitment basis lets us evaluate the polynomial f_S at a given secret v wihtout revealing v itself.
        
    

        Implementation note:
        
        """

        basisElement = self.g1
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey
            commitmentBasis.append(basisElement)
        #return commitment basis
        return commitmentBasis


    def sigmaProtocol(self, randomScalar, commitmentBasis):
        
        """
        Notation in paper and our correlating naming scheme:

        Used by:
        
        Why we do this:

        Implementation note:
        
        """
        
        # creates the sigma sequence by upscaling each element from the prior by the random scalar
        sigmaSequence = []
        for i in range(len(commitmentBasis)):
            sigmaI = commitmentBasis[i] * randomScalar
            sigmaSequence.append(sigmaI)

        return sigmaSequence


    def keyGen(self, upperBound):

        
        """
        Notation in paper and our correlating naming scheme:

        Used by:
        
        Why we do this:

        Implementation note:
        
        """

        secretKey = self.group.random(ZR)
        commitmentBasis = self.buildCommitmentBasis(secretKey, upperBound)

        randomScalar = self.group.random(ZR)
        announcement = self.sigmaProtocol(randomScalar, commitmentBasis[:-1])
        challenge = self.hashForChallenge((announcement, commitmentBasis))
        response = randomScalar + challenge * secretKey

        return secretKey, challenge, response, commitmentBasis
    

    def verifyIssuerParameter(self, challenge, response, commitmentBasis):
        
        """
        Notation in paper and our correlating naming scheme:

        
        
        """

        proposedChallenge = []
        sigmaOutPut = self.sigmaProtocol(response, commitmentBasis[:-1])

        # Compute the proposed challenge 
        for i in range(len(commitmentBasis) - 1):
            proposedChallenge.append(sigmaOutPut[i] - (challenge * commitmentBasis[i + 1]))

        challengeCheck = self.hashForChallenge((proposedChallenge, commitmentBasis))

        return challengeCheck == challenge
        

    def commit(self, commitmentBasis, disclosedAttributes):

        """
        Notation in paper and our correlating naming scheme:

        Used by:
        
        Why we do this:

        Implementation note:
        
        """

        # Get polynomial coefficients
        coefficients = self.createPolynomial(disclosedAttributes)
        
        # Create and return commitment
        commitment = self.createCommitment(coefficients, commitmentBasis)   
        return commitment, self.gPrime


    def randomize(self, commitment1, commitment2, randomScalarMu):

        """
        Notation in paper and our correlating naming scheme:

        Used by:
        
        Why we do this:

        Implementation note:
        
        """

        newCommitment1 = commitment1 * randomScalarMu
        newCommitment2 = commitment2 * randomScalarMu

        return newCommitment1, newCommitment2


    def verifySubset(self, secretKey, randomizedCommitment, witness, disclosedAttributeSubset):
        
        """
        Notation in paper and our correlating naming scheme:

        Used by:
        
        Why we do this:

        Implementation note:
        
        """

        # Evaluate f_D at the secret key v and combine it with the witness
        # to reconstruct the commitment value that should match C'
        polynomialAtSecret = self.evaluatePolynomialForVerification(disclosedAttributeSubset, secretKey)
        commitment = polynomialAtSecret * witness

        # Check that the reconstructed commitment value matches the randomized commitment
        return randomizedCommitment == commitment