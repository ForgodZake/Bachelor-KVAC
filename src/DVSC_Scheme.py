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
    - challenge, response: corresponds to the Fiat-Shamir style proof of knowledge π used to show knowledge of v (secret Key) behind the basis.
    - disclosedAttributes: corresponds to the set S, represented as already hashed field elements in Z_p.
    - disclosedAttributeSubset: corresponds to the subset D ⊆ S, represented as already hashed field elements in Z_p.
    - commitment: C = (C_1, C_2) = (f_S(v)G, G').
    - randomizedCommitment: C' = (μf_S(v)G, μG').
    - witness: W = μf_{S\D}(v)G.
    - randomScalarMu: μ ∈ Z_p*.
    
    Implementation note:
    This class assumes attribute inputs (disclosedAttributes) have already been encoded as field elements in Z_p.
    In other words, hashing or encoding of the attribute components are assumed to be done externally.
    
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
        - upperBound: corresponds to t, the uppper bound of the given set of attributes.
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G
        
        Why we do this:
        buildCommitmentBasis() is a helper function used in keyGen().
        The commitment basis lets us evaluate the polynomial f_S at a given secret v without revealing v itself.
        Since the polynomial at secret v is computed as f_S(v) = sum_i f_i V_i we can get around knowing v by using the basis.

        Implementation note:
        
        """

        basisElement = self.g1
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey
            commitmentBasis.append(basisElement)
        #return commitment basis
        return commitmentBasis


    def buildSigmaAnnouncement(self, randomScalar, commitmentBasis):
        
        """
        A helper function which computes the Announcement used in the sigma protocol when proving knowledge of the secret v. 

        Used by:
        - Issuer uses this in keyGen(), when computing the proof (π).
        - User uses this doing verifyIssuerParameter(), when checking the proof.

        Notation in paper and our correlating naming scheme:
        - randomScalar: Is the fresh randomness used for the sigmaProtocol.
        - commitmentBasis: hold our (V_0, ..., V_t).
        - announcementSequence: which accumulates the announcement values of the proof.
        
        Why we do this:
        The scheme uses a proof of knowledge π showing the basis in ipar satifying:
        V_{j+1} = vV_j or that the basis indeed is computed from the secret v.
        The announcement sequence is used to blind the proof of knowledge of the secret scalar v behind the commitment basis.
        It allows the issuer to prove that the basis was generated consistently from one hidden value v, without revealing v itself.

        """
        
        # creates the announcement sequence by upscaling each element from the prior by the random scalar
        announcementSequence = []
        for i in range(len(commitmentBasis)):
            announcementI = commitmentBasis[i] * randomScalar
            announcementSequence.append(announcementI)

        return announcementSequence


    def keyGen(self, upperBound):

        """
        KeyGen() generates the secret v as well as the public issuer parameter ipar.
        Ipar consist of the commitmentBasis and the its proof of knowledge.

        Used by:
        - Issuer uses KeyGen() to set up initial secret key and public parameters.

        Notation in paper and our correlating naming scheme:
        - secretKey: sk = v where v ∈ Z_p*.
        - upperBound: corresponds to t, the uppper bound of the given set of attributes.
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G.
        - challenge, response: are part of the Fiat-Shamir proof π which is part of ipar together with the commitmentBasis.  
        
        Why we do this:
        KeyGen() makes the setup for both users and issuer/verifier. the screKey is used in computing the basis and challenge.
        When verifying subset the secretKey is further used to confirm validity. 
        The public issuer paramaters ipar can be used by users to compute commitments and subset openings.
        The proof π can then be used by verifier to check that the basis is generated by the scalar v. 
        
        """

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
        
        """
        VerifyIssuerParameter() is used to verify that the proof π is created based on the secret v. 

        Used by:
        - User uses the check to guarantee that they can build commitments based on the basis.
        This computation should only be done once by user, as it's expensive and the basis should not change.
        When the basis has been verified by user, they can create any commitment they have valid attributes for.

        Notation in paper and our correlating naming scheme:
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G.
        - challenge, response: are part of the Fiat-Shamir proof π which is part of ipar together with the commitmentBasis. 

        Why we do this:
        The security of commitments made by users are based on the issuer parameters.
        The verification is done by recomputing the sigmaAnnouncement from the response and challenge. 
        These are serialized and hashed to check against the challenge.         
        
        """

        proposedChallenge = []
        sigmaOutPut = self.buildSigmaAnnouncement(response, commitmentBasis[:-1])

        # Compute the proposed challenge 
        for i in range(len(commitmentBasis) - 1):
            proposedChallenge.append(sigmaOutPut[i] - (challenge * commitmentBasis[i + 1]))

        challengeCheck = self.hashForChallenge((proposedChallenge, commitmentBasis))

        return challengeCheck == challenge
        

    def commit(self, commitmentBasis, disclosedAttributes):

        """
        Commit() computes the commitment C for a S as C = (f_S(v)G, G').

        Used by:
        - User uses commit() to create credentials, which is the representation of the attributes given to the verifier. 
         
        Notation in paper and our correlating naming scheme:
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G.
        - disclosedAttributes: is the corresponding set S of attributes hashed to Z_p.
        - commitment: is the computed represention: C = (f_S(v)G, G').
        
        Why we do this:
        Creating the commitment using the polynomial guarantees us a deterministic commitment.
        The commitment is created by evaluating the polynomial at the secret and scaling it by the group element of prime group 1.
        The commitment consist of two different elements as we wanna prevent that any element can be scaled into another when randomizing.

        """

        # Get polynomial coefficients
        coefficients = self.createPolynomial(disclosedAttributes)
        
        # Create and return commitment
        commitment = self.createCommitment(coefficients, commitmentBasis)

        return commitment, self.gPrime


    def randomize(self, commitment1, commitment2, randomScalarMu):

        """
        randomize() randomizes a commitment into an equally valid commitment C' = (μC_1, μC_2).

        Used by:
        - User uses this to randomize their commitment before each presentation to verifer. 

        Notation in paper and our correlating naming scheme:
        - commitment1, commitment2: corresponds to C = (C_1, C_2).
        - randomScalarMu: μ ∈ Z_p*.
        
        Why we do this:
        The scalar is in Z_p* so it remains inside the same equivalence class,
        but creates randomly scaled commitments which are indistinguishable from eachother but retain validity of commitment.
        
        """

        newCommitment1 = commitment1 * randomScalarMu
        newCommitment2 = commitment2 * randomScalarMu

        return newCommitment1, newCommitment2


    def verifySubset(self, secretKey, randomizedCommitment, witness, disclosedAttributeSubset):
        
        """
        VerifySubset() checks that the given commitment send by user opens to the subset of required attributes D.

        Used by:
        - Verifier uses this method to check the validity of a users presentation.

        Notation in paper and our correlating naming scheme:
        - secretKey: sk = v where v ∈ Z_p*.
        - randomizedCommitment: C' = μf_S(v)G.
        - witness: W = μf_{S\D}(v)G.
        - disclosedAttributes: is the corresponding set S of attributes hashed to Z_p.
        - disclosedAttributeSubset: is the corresponding set D ⊆ S of attributes hashed to Z_p.

        Why we do this:
        The verifier can check the validity of the commitment from the user with the given witness by checking C'_1 = f_D(v) · W.
        This works as W = μf_{S\D}(v)G and since f_S(X) = f_D(X)f_{S\D}(X), multiplying W by f_D(v) reconstructs μf_S(v)G = C'_1.
        The function will then return a boolean based on whether the recomputed commitment matches the given randomized one.    
        
        """

        # Evaluate f_D at the secret key v and combine it with the witness
        # to reconstruct the commitment value that should match C'
        polynomialAtSecret = self.evaluatePolynomial(disclosedAttributeSubset, secretKey)
        commitment = polynomialAtSecret * witness

        # Check that the reconstructed commitment value matches the randomized commitment
        return randomizedCommitment == commitment