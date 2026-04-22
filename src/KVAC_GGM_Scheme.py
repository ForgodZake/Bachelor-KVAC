
from Common_DVSC_Functions import Common_DVSC_Functions

class KVAC_GGM(Common_DVSC_Functions):

    def __init__(self, groupObject):
        super().__init__(groupObject)
        

    def keyGen(self):

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

        basisElement = self.g1 ** y
        commitmentBasis = [basisElement]

        for i in range(upperBound):

            basisElement = basisElement ** secretKey
            commitmentBasis.append(basisElement)

        #return commitment basis
        return commitmentBasis
    

    def sigmaProtocol(self, commitment, iparR, basis, x, v):
        sigma_C = commitment ** x
        sigma_R = iparR ** x

        sigma_basis = []

        for i in range(len(basis)-1):

            basisElement = basis[i] ** v
            sigma_basis.append(basisElement)

        return sigma_C, sigma_R, sigma_basis        


    def buildPIResponse(self, random_x, random_v, challenge, secret_x, secret_v):
        response_x = random_x + challenge * secret_x
        response_v = random_v + challenge * secret_v

        return response_x, response_v


    def makeNIZK(self, secret_x, secret_v, commitment, ipar, basis, tagTau, attributesRaw):

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

        #get secret keys and ipar
        secret_x, secret_v = isk

        #sample random y
        y = self.group.random(self.scalarType)
        
        polynomial = self.evaluatePolynomialForVerification(disclosedAttributes, secret_v)

        commitment = (self.g1 ** (y * polynomial))

        #compute the tag tau
        tagTau = commitment ** secret_x

        #compute Yj(basis)
        basis = self.buildCommitmentBasis(secret_v, len(disclosedAttributes), y)

        #proof time :)
        pi = self.makeNIZK(secret_x, secret_v, commitment, ipar, basis, tagTau, disclosedAttributes)

        return tagTau, basis, pi
    

    def obtainCred(self, tagTau, basis, pi, disclosedAttributes, ipar):

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

        #Make sure that tag is not base element
        if randomizedTagTau == self.groupIdentity():
            return False
        
        #get keys
        secret_x, secret_v = isk

        # Hash attributes to ZR space and compute polynomail
        polynomial = self.evaluatePolynomialForVerification(requiredAttributeSubset, secret_v)

        #make sure that its equal to the tag
        check = witness ** (secret_x * polynomial)
        return check == randomizedTagTau