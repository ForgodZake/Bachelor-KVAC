
from Common_DVSC_Functions import Common_DVSC_Functions

class KVAC_GGM(Common_DVSC_Functions):


    """
    
    Implementation of the pairingless KVAC construction, denoted KVAC-GGM in this report.
    This construction is described in Section 6 of Keyed-Verification Anonymous Credentials with Highly Efficient Partial Disclosure.

    KVAC-GGM combines: 
    - A homomorphic MAC: used to authenticate a set commitment.
    - DVSC-style polynomial commitments: used to commit to an attribute set S and later open a subset D ⊆ S.

    Instead of utilizing SP-MAC-EQ and bilinear pairing like the KVAC_MEQ implementation,
    the KVAC-GGM implementation works through a single cyclic group and uses homomorphic property of the MAC when verifying credentials.

    The issuer creates the commitment C on the user full attributeset S.
    The commitmnet is authenticated via the MAC tag τ = xC.
    Here the secret key x is used to blind the credential.
    
    When presenting, the user randomizes the tag and computes a corresponding witness W, for the disclosed subset D.
    Verfier can then check if the randomized tag is valid for a correspondign credentail,
    and further check that D is contained within the original committed set S.

    Notation in paper and our correlating naming scheme: 
    - secret_x: corresponds to x, the MAC secret key.
    - secret_v: corresponds to v, the secret evaluation point used in the set commitment.
    - r: corresponds to the blinding scalar used in the public issuer parameters.
    - isk: issuer secret key, isk = (x, v).
    - ipar: public issuer parameters, ipar = (R, X, V) = (rG, rxG, vG).
    - disclosedAttributes: corresponds to the full attribute set S, represented as field elements in Z_p.
    - requiredAttributeSubset: corresponds to the disclosed subset D ⊆ S.
    - y: per-credential randomness used when creating the commitment.
    - commitment: corresponds to C = f_S(v)yG.
    - tagTau: corresponds to τ = xC.
    - basis: corresponds to (Y_j) where Y_j = yv^jG.
    - pi: NIZK proof showing consistency between the public issuer parameters, the tag, and the basis.
    - randomScalarMu: corresponds to μ, the presentation randomization scalar.
    - randomizedTagTau: corresponds to τ' = μτ. 
    - witness: corresponds to W = μy f_{S\D}(v)G.

    Implementation note: This class inherits from Common_DVSC_Functions because the polynomial helpers,
    commitment computation, subset opening, and challenge hashing logic are shared between DVSC and KVAC-GGM.
    """

    def __init__(self, groupObject):

        """
        Initializes the KVAC-GGM scheme with group context.
        This is done through the super class Common_DVSC_Functions.

        Used by:
        - Issuer/verifier to setup the KVAC-GGM scheme.

        Notation in paper and our correlating naming scheme:
        - groupObject: corresponds to the cyclic group setting used in the scheme.
        - self.g1: corresponds to the generator G.

        Why we do this:
        The KVAC-GGM only needs the one cyclic group, when initialized via the super class,
        it detects the group type, which is used from the charm library, and initializes the generator self.g1.
        This makes it, so helper functions from Common_DVSC_Functions can be used, without also using the pairing relation.
        """

        super().__init__(groupObject)
        

    def keyGen(self):

        """
            keyGen() generates the issuer secret key and public issuer parameters.

            Used by:
            - Issuer/verifier when setting up the scheme.

            Notation in paper and our correlating naming scheme:
            - x: corresponds to the MAC secret key.
            - v: corresponds to the secret evaluation point for the set commitment.
            - r: corresponds to the blinding scalar used in the public issuer parameters.
            - isk: corresponds to the issuer secret key isk = (x, v).
            - iparR: corresponds to R = rG.
            - iparX: corresponds to X = rxG.
            - iparv: corresponds to V = vG.
            - ipar: corresponds to the public issuer parameters ipar = (R, X, V).
            
            Why we do this:
            When verifying the credential presentation, the verifier needs access to the two secrets x and v.
            These are values unknown to the user, but through the use of the public parameters,
            the user can check that an issued credential is based on the x and v.
            R and X bind the MAC key x through the blinding scalar r,
            while V binds the set commitment secret v to a public group element.
        """

        generator = self.g1

        x = self.group.random(self.scalarType)
        v = self.group.random(self.scalarType)
        r = self.group.random(self.scalarType)

        #make the secret key
        isk = (x, v)

        #compute the public parameters
        iparR = generator ** r
        iparX =  generator ** (r * x)
        iparv = generator ** v

        ipar = (iparR, iparX, iparv)

        return isk, ipar
    

    def buildCommitmentBasis(self, secretKey, upperBound, y):

        """
        buildCommitmentBasis() builds the per-credential basis (Y_0, ..., Y_t).

        Used by:
        - Issuer during issueCred(), when creating the basis sent to the user.

        Notation in paper and our correlating naming scheme:
        - secretKey: corresponds to v, the secret set commitment evaluation point.
        - upperBound: corresponds to the size of the attribute set.
        - y: corresponds to the per-credential randomness sampled by the issuer.
        - commitmentBasis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.

        Why we do this:
        The user needs to recompute the commmitment (C = f_S(v)yG) without the knowledge of the secret v.
        The polynomial coefficients of f_S(X) can be represented as its coefficients, and
        coefficients can be computed either via the secret v or the commitment basis, f_S(v)yG = Σ_i f_iY_i.
    
        """

        basisElement = self.g1 ** y
        commitmentBasis = [basisElement]

        for i in range(upperBound):

            basisElement = basisElement ** secretKey
            commitmentBasis.append(basisElement)

        #return commitment basis
        return commitmentBasis
    

    def sigmaProtocol(self, commitment, iparR, basis, x, v):
        
        """
        sigmaProtocol() computes the Sigma-protocol relation values used in the NIZK proof.

        Used by:
        - Issuer to compute the random announcement in makeNIZK().
        - User to recompute the accepting announcement in verifyNIZK().


        Notation in paper and our correlating naming scheme:
        - commitment: corresponds to C = f_S(v)yG.
        - iparR: corresponds to R = rG.
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - x: is either the real MAC key, a random mask, or a proof response.
        - v: is either the real set commitment secret, a random mask, or a proof response.
        - sigma_C: corresponds to xC.
        - sigma_R: corresponds to xR.
        - sigma_basis: corresponds to vY_i for each basis element Y_i.

        Why we do this:
        Sigma is used through the NIZK proof, a
       
        """

        sigma_C = commitment ** x
        sigma_R = iparR ** x

        sigma_basis = []

        for i in range(len(basis)-1):

            basisElement = basis[i] ** v
            sigma_basis.append(basisElement)

        return sigma_C, sigma_R, sigma_basis        


    def buildPIResponse(self, random_x, random_v, challenge, secret_x, secret_v):
    
        """
        buildPIResponse() builds the response values for the Fiat-Shamir transformed proof.

        Used by:
        - Issuer in makeNIZK(), after the challenge has been computed.
        
        Notation in paper and our correlating naming scheme:
        - random_x: corresponds to the random mask for x.
        - random_v: corresponds to the random mask for v.
        - challenge: corresponds to the Fiat-Shamir challenge c.
        - secret_x: corresponds to the MAC secret key x.
        - secret_v: corresponds to the set commitment secret v.
        - response_x: corresponds to s_x = random_x + c*x.
        - response_v: corresponds to s_v = random_v + c*v.

        Why we do this:
       
        """

        response_x = random_x + challenge * secret_x
        response_v = random_v + challenge * secret_v

        return response_x, response_v


    def makeNIZK(self, secret_x, secret_v, commitment, ipar, basis, tagTau, attributesRaw):

        """
        makeNIZK() creates the NIZK proof π for an issued credential.

        Used by:
        - Issuer during issueCred().

        Notation in paper and our correlating naming scheme:
        - secret_x: corresponds to x, the MAC secret key.
        - secret_v: corresponds to v, the set commitment secret.
        - commitment: corresponds to C = f_S(v)yG.
        - ipar: corresponds to the public issuer parameters (R, X, V).
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - tagTau: corresponds to τ = xC. 
        - attributesRaw: corresponds to the full attribute set S.
        - pi: corresponds to the proof π = (challenge, finalProof_x, finalProof_v).

        Why we do this:
       
        """

        iparR, iparX, ipar_v = ipar 

        random_x = self.group.random(self.scalarType)
        random_v = self.group.random(self.scalarType)

        #compute announceent
        announcement = self.sigmaProtocol(commitment, iparR, basis, random_x, random_v)

        #compute hash
        hashSequence = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement)
        challenge = self.hashForChallenge(hashSequence)

        #make the proof x and v from building the PI response
        finalProof_x, finalProof_v = self.buildPIResponse(random_x, random_v, challenge, secret_x, secret_v)
        return (challenge, finalProof_x, finalProof_v)

        
    def verifyNIZK(self, pi, commitment, ipar, basis, tagTau, attributesRaw):

        """
        verifyNIZK() verifies the NIZK proof π computed during credential issuance.

        Used by:
        - User during obtainCred(), before accepting the credential.

        Notation in paper and our correlating naming scheme:
        - pi: corresponds to the proof π = (challenge, proof_x, proof_v).
        - commitment: corresponds to C = f_S(v)yG, reconstructed by the user.
        - ipar: corresponds to the public issuer parameters (R, X, V).
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - tagTau: corresponds to τ = xC. - attributesRaw: corresponds to the full attribute set S.
        - userChallengeHash: corresponds to the verifier's recomputed challenge.

        Why we do this:
       
        """

        challenge, proof_x, proof_v = pi
        iparR, iparX, ipar_v = ipar

        # Compute the announcement
        sigmaAnnouncementC, sigmaAnnouncementR, sigmaAnnouncementBasis = self.sigmaProtocol(commitment, iparR, basis, proof_x, proof_v)
        announcementTagTau = sigmaAnnouncementC / (tagTau ** challenge)
        announcementX = sigmaAnnouncementR / (iparX ** challenge)

        announcement_basis = []
        for i in range(len(basis)-1):
            announcement_basis.append(sigmaAnnouncementBasis[i] / (basis[i+1] ** challenge))

        announcement = (announcementTagTau, announcementX, announcement_basis)

        #compute the challenge
        userChallenge = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement)
        userChallengeHash = self.hashForChallenge(userChallenge)

        return challenge == userChallengeHash


    def issueCred(self, disclosedAttributes, isk, ipar):

        """
        issueCred() creates a credential on the user's full attribute set S.

        Used by:
        - Issuer to create the credential.

        Notation in paper and our correlating naming scheme:
        - disclosedAttributes: corresponds to the committed attribute set S.
        - isk: corresponds to the issuer secret key isk = (x, v).
        - ipar: corresponds to the public issuer parameters (R, X, V).
        - y: corresponds to the per-credential randomness.
        - polynomial: corresponds to f_S(v).
        - commitment: corresponds to C = f_S(v)yG.
        - tagTau: corresponds to τ = xC.
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - pi: corresponds to the NIZK proof of consistency.

        Why we do this:
       
        """

        #get secret keys and ipar
        secret_x, secret_v = isk

        #sample random y
        y = self.group.random(self.scalarType)
        
        polynomial = self.evaluatePolynomial(disclosedAttributes, secret_v)

        commitment = (self.g1 ** (y * polynomial))

        #compute the tag tau
        tagTau = commitment ** secret_x

        #compute Yj(basis)
        basis = self.buildCommitmentBasis(secret_v, len(disclosedAttributes), y)

        #proof time :)
        pi = self.makeNIZK(secret_x, secret_v, commitment, ipar, basis, tagTau, disclosedAttributes)

        return tagTau, basis, pi
    

    def obtainCred(self, tagTau, basis, pi, disclosedAttributes, ipar):

        """
        obtainCred() verifies and stores the credential received from the issuer.

        Used by:
        - User after receiving the pre-credential from the issuer.
        
        Notation in paper and our correlating naming scheme:
        - tagTau: corresponds to τ = xC.
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - pi: corresponds to the NIZK proof returned by the issuer.
        - disclosedAttributes: corresponds to the user's full attribute set S.
        - ipar: corresponds to the public issuer parameters (R, X, V).
        - commitment: corresponds to the reconstructed commitment C = f_S(v)yG.

        Why we do this:
       
        """

        # Compute polynomial
        coefficients = self.createPolynomial(disclosedAttributes)
        commitment = self.groupIdentity()
        
        for coeff, baseElement in zip(coefficients, basis):
            commitment = commitment * (baseElement ** coeff)

        #make sure commitment is not the basis element
        if commitment == self.groupIdentity():
            return None
        
        # verify zero knowledge and get check
        check = self.verifyNIZK(pi, commitment, ipar, basis, tagTau, disclosedAttributes)
       
        #check that the challenge computed on user and issuer side are the same
        if check == False:
            return None
        
        return tagTau, basis
    

    def showCred(self, tagTau, basis, disclosedAttributes, requiredAttributeSubset):

        """
        showCred() creates a randomized credential presentation.

        Used by:
        - User when presenting a credential to a verifier.

        Notation in paper and our correlating naming scheme:
        - tagTau: corresponds to the credential tag τ = xC.
        - basis: corresponds to (Y_0, ..., Y_t), where Y_j = yv^jG.
        - disclosedAttributes: corresponds to the full committed attribute set S.
        - requiredAttributeSubset: corresponds to the disclosed subset D ⊆ S.
        - randomScalarMu: corresponds to μ.
        - randomizedTagTau: corresponds to τ' = μτ.
        - witness: corresponds to W = μy f_{S\D}(v)G.
        
        Why we do this:
       
        """

        #get random mu and make sure it is not 0
        randomScalarMu = self.group.random(self.scalarType)
        while randomScalarMu == self.scalarZero():
            randomScalarMu = self.group.random(self.scalarType)

        #check that subset is actually a subset for the attribute set
        if not all(attribute in disclosedAttributes for attribute in requiredAttributeSubset):
            return None
        
        #make the witness
        witness = self.openSubset(basis, disclosedAttributes, requiredAttributeSubset, randomScalarMu)

        #randomize the tag
        randomizedTagTau = tagTau ** randomScalarMu

        return randomizedTagTau, witness
    

    def verify(self, randomizedTagTau, witness, requiredAttributeSubset, isk):

        """
        verify() verifies a randomized KVAC-GGM credential presentation.

        Used by:
        - Verifier when checking a user's credential presentation.

        Notation in paper and our correlating naming scheme:
        - randomizedTagTau: corresponds to the randomized tag τ' = μτ.
        - witness: corresponds to W = μy f_{S\D}(v)G. - requiredAttributeSubset: corresponds to the disclosed subset D.
        - isk: corresponds to the issuer/verifier secret key isk = (x, v).
        - polynomial: corresponds to f_D(v).

        Why we do this:
       
        """

        #Make sure that tag is not base element
        if randomizedTagTau == self.groupIdentity():
            return False
        
        #get keys
        secret_x, secret_v = isk

        # Hash attributes to ZR space and compute polynomail
        polynomial = self.evaluatePolynomial(requiredAttributeSubset, secret_v)

        #make sure that its equal to the tag
        check = witness ** (secret_x * polynomial)
        return check == randomizedTagTau