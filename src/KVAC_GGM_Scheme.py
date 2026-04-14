from charm.toolbox.pairinggroup import G1, ZR
from PolyCommmitBase import PolyCommitBase

class KVAC_GGM(PolyCommitBase):

    def __init__(self, groupObject):

        super().__init__(groupObject, groupObject.random(G1))
        

    def keyGen(self):

        generator = self.g1

        x = self.group.random(ZR)
        v = self.group.random(ZR)
        r = self.group.random(ZR)

        #make the secret key
        isk = (x, v)

        #compute the public parameters
        iparR = r * generator
        iparX = r * x * generator
        iparv = v * generator

        ipar = (iparR, iparX, iparv)

        return isk, ipar
    
    def buildCommitmentBasis(self, secretKey, upperBound, y):

        basisElement = y * self.g1
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey

            commitmentBasis.append(basisElement)
        #return commitment basis
        return commitmentBasis
    
    def sigmaProtocol(self, commitment, iparR, basis, x, v):
        sigma_C = x * commitment
        sigma_R = x * iparR
        sigma_basis = []
        for i in range(len(basis)-1):
            basisElement = v * basis[i]
            sigma_basis.append(basisElement)

        return sigma_C, sigma_R, sigma_basis        
    
    def hashForChallenge(self, announcementSequence):

        # convert announcement to byterepresentation for hashing
        byteRepresentation = self.toBytes(announcementSequence)

        return self.group.hash(byteRepresentation, ZR)
    
    def toBytes(self, announcementSequence):

        # If announcementSequence is string encode 
        if isinstance(announcementSequence, str):
            return announcementSequence.encode("utf-8")

        # If announcementSequence is list or tuble recursively access each element,
        # and concatenate encoding/serialization to result.
        if isinstance(announcementSequence, (list, tuple)):
            result = b""
            for item in announcementSequence:
                result += self.toBytes(item) + b"||"
            return result

        # Otherwise serialize elements from group objects (G1, G2, ZR elements)
        return self.group.serialize(announcementSequence)
    

    def buildPIResponse(self, random_x, random_v, challenge, secret_x, secret_v):
        response_x = random_x + challenge * secret_x
        response_v = random_v + challenge * secret_v

        return response_x, response_v

    def makeNIZK(self, secret_x, secret_v, commitment, ipar, basis, tagTau, attributesRaw):

        iparR, iparX, ipar_v = ipar 

        random_x = self.group.random(ZR)
        random_v = self.group.random(ZR)

        #compute announceent
        announcement = self.sigmaProtocol(commitment, iparR, basis, random_x, random_v)

        #compute hash
        hashSequence = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement)
        challenge = self.hashForChallenge(hashSequence)

        #make the proof x and v from building the PI response
        finalProof_x, finalProof_v = self.buildPIResponse(random_x, random_v, challenge, secret_x, secret_v)
        return (challenge, finalProof_x, finalProof_v)

        
    def verifyNIZK(self, pi, commitment, ipar, basis, tagTau, attributesRaw):

        challenge, proof_x, proof_v = pi
        iparR, iparX, ipar_v = ipar

        # Compute the announcement
        sigmaAnnouncementC, sigmaAnnouncementR, sigmaAnnouncementBasis = self.sigmaProtocol(commitment, iparR, basis, proof_x, proof_v)
        announcementTagTau = sigmaAnnouncementC - (challenge * tagTau)
        announcementX = sigmaAnnouncementR - (challenge * iparX)

        announcement_basis = []
        for i in range(len(basis)-1):
            announcement_basis.append(sigmaAnnouncementBasis[i] - (challenge * basis[i+1]))

        announcement = (announcementTagTau, announcementX, announcement_basis)

        #compute the challenge
        userChallenge = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement)
        userChallengeHash = self.hashForChallenge(userChallenge)

        if challenge != userChallengeHash:
            return False

        return True

    def issueCred(self, attributesRaw, isk, ipar):

        #get secret keys and ipar
        secret_x, secret_v = isk

        #sample random y
        y = self.group.random(ZR)

        # Hash attributes to ZR space and build polynomial
        attributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]
        coefficents = self.createPolynomial(attributes)
        polynomial = self.evaluatePolynomial(coefficents, secret_v)
        commitment = (y * polynomial * self.g1)

        #compute the tag tau
        tagTau = secret_x * commitment

        #compute Yj(basis)
        basis = self.buildCommitmentBasis(secret_v, len(attributesRaw), y)

        #proof time :)
        pi = self.makeNIZK(secret_x, secret_v, commitment, ipar, basis, tagTau, attributesRaw)

        return tagTau, basis, pi
    

    def obtainCred(self, tagTau, basis, pi, attributesRaw, ipar):

        # Hash attributes to ZR space
        attributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]

        # Compute polynomial
        coefficients = self.createPolynomial(attributes)
        commitment = self.group.init(G1)
        for coeff, baseElement in zip(coefficients, basis):
            commitment += coeff * baseElement

        #make sure commitment is not the basis element
        if commitment == self.group.init(G1):
                return None
        
        # verify zero knowledge and get check
        check = self.verifyNIZK(pi, commitment, ipar, basis, tagTau, attributesRaw)
       
        #check that the challenge computed on user and issuer side are the same
        if check == False:
            return None
        
        return tagTau, basis
    

    def showCred(self, tagTau, basis, attributesRaw, requiredAttributeSubsetRaw):

        #get random mu and make sure it is not 0
        randomScalarMu = self.group.random(ZR)
        while randomScalarMu == self.group.init(ZR):
            randomScalarMu = self.group.random(ZR)

        #check that subset is actually a subset for the attribute set
        if not all(attribute in attributesRaw for attribute in requiredAttributeSubsetRaw):
            return None
        
        #make the witness
        witness = self.openSubset(basis, attributesRaw, requiredAttributeSubsetRaw, randomScalarMu)

        #randomize the tag
        randomizedTagTau = randomScalarMu * tagTau

        return randomizedTagTau, witness
    

    def verify(self, randomizedTagTau, witness, subset, isk):

        #Make sure that tag is not base element
        if randomizedTagTau == self.group.init(G1):
            return False
        
        #get keys
        secret_x, secret_v = isk

        # Hash attributes to ZR space and compute polynomail
        attributes = [self.group.hash(attribute, ZR) for attribute in subset]
        coefficients = self.createPolynomial(attributes)
        polynomial = self.evaluatePolynomial(coefficients, secret_v)

        #make sure that its equal to the tag
        check = secret_x * witness * polynomial
        if check == randomizedTagTau:
            return True
        
        return False