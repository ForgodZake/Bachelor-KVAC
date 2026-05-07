
from Common_DVSC_Functions import Common_DVSC_Functions

class KVAC_GGM(Common_DVSC_Functions):

    def __init__(self, groupObject):
        super().__init__(groupObject)
        

    def keyGen(self):

        generator = self.g1

        x1 = self.group.random(self.scalarType)
        x2 = self.group.random(self.scalarType)
        x3 = self.group.random(self.scalarType)
        secretKeyMac = x1,x2,x3

        secretKeySetCommitment = self.group.random(self.scalarType)
        r = self.group.random(self.scalarType)

        #make the secret key
        isk = (secretKeyMac, secretKeySetCommitment)

        #compute the public parameters
        iparR = generator ** r
        iparX1 = generator ** (r * x1) 
        iparX2 = generator ** (r * x2)
        iparX3 = generator ** (r * x3)
        iparX = iparX1, iparX2, iparX3
        iparv = generator ** secretKeySetCommitment

        ipar = (iparR, iparX, iparv)

        return isk, ipar, self.gPrime
    

    def buildCommitmentBasis(self, secretKey, upperBound, y):

        basisElement = self.g1 ** y
        commitmentBasis = [basisElement]

        for i in range(upperBound):

            basisElement = basisElement ** secretKey
            commitmentBasis.append(basisElement)

        #return commitment basis
        return commitmentBasis
    

    def sigmaProtocol(self, commitment, iparR, upk, basis, x1, x2, x3, v):

        sigma_C = (commitment ** x1) * (self.gPrime ** x2) * (upk ** x3)
        sigma_R1 = iparR ** x1
        sigma_R2 = iparR ** x2
        sigma_R3 = iparR ** x3

        sigma_basis = []

        for i in range(len(basis)-1):

            basisElement = basis[i] ** v
            sigma_basis.append(basisElement)

        return sigma_C, (sigma_R1, sigma_R2, sigma_R3), sigma_basis        


    def buildPIResponse(self, random_x1, random_x2, random_x3, random_v, challenge, secretKeyMac, secret_v):
        
        secret_x1, secret_x2, secret_x3 = secretKeyMac
        response_x1 = random_x1 + challenge * secret_x1
        response_x2 = random_x2 + challenge * secret_x2
        response_x3 = random_x3 + challenge * secret_x3
        response_v = random_v + challenge * secret_v

        return (response_x1, response_x2, response_x3), response_v


    def makeNIZK(self, secretKeyMac, secretKeySetCommitment, commitment, ipar, basis, tagTau, attributesRaw, upk):

        iparR, iparX, ipar_v = ipar

        random_x1 = self.group.random(self.scalarType)
        random_x2 = self.group.random(self.scalarType)
        random_x3 = self.group.random(self.scalarType)
        random_v = self.group.random(self.scalarType)

        #compute announceent
        announcement = self.sigmaProtocol(commitment, iparR, upk, basis, random_x1, random_x2, random_x3, random_v)

        #compute hash
        hashSequence = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement, upk)
        challenge = self.hashForChallenge(hashSequence)

        #make the proof x and v from building the PI response
        finalProof_x, finalProof_v = self.buildPIResponse(random_x1, random_x2, random_x3, random_v, challenge, secretKeyMac, secretKeySetCommitment)
        return (challenge, finalProof_x, finalProof_v)

        
    def verifyNIZK(self, pi, commitment, ipar, basis, tagTau, attributesRaw, upk):

        challenge, proof_x, proof_v = pi
        proof_x1, proof_x2, proof_x3 = proof_x
        iparR, iparX, ipar_v = ipar
        iparX1, iparX2, iparX3 = iparX

        # Compute the announcement
        sigmaAnnouncementC, sigmaAnnouncementR, sigmaAnnouncementBasis = self.sigmaProtocol(commitment, iparR, upk, basis, proof_x1, proof_x2, proof_x3, proof_v)
        sigmaAnnouncementR1, sigmaAnnouncementR2, sigmaAnnouncementR3 = sigmaAnnouncementR 
        
        announcementX1 = sigmaAnnouncementR1 / (iparX1 ** challenge)
        announcementX2 = sigmaAnnouncementR2 / (iparX2 ** challenge)
        announcementX3 = sigmaAnnouncementR3 / (iparX3 ** challenge)

        announcementTagTau = sigmaAnnouncementC / (tagTau ** challenge)
        announcement_basis = []
        for i in range(len(basis)-1):
            announcement_basis.append(sigmaAnnouncementBasis[i] / (basis[i+1] ** challenge))

        announcement = (announcementTagTau, (announcementX1, announcementX2, announcementX3), announcement_basis)

        #compute the challenge
        userChallenge = (attributesRaw, tagTau, ipar_v, commitment, iparX, iparR, basis, announcement, upk)
        userChallengeHash = self.hashForChallenge(userChallenge)

        return challenge == userChallengeHash

    def makeNIZKnonTransferable(self, usk, randomizedGPrime, randomizedUpk, ipar, randomizedCommitment, randomizedTag, disclosedSubset, subsetWitness):
    
        randomizer = self.group.random(self.scalarType)
        randomizedAnnouncement =  randomizedGPrime ** randomizer

        challengeAnnouncement = (ipar, randomizedCommitment, randomizedTag, randomizedGPrime, randomizedUpk, disclosedSubset, subsetWitness, randomizedAnnouncement)
        challenge = self.hashForChallenge(challengeAnnouncement)
        
        proofResponse = randomizer + challenge * usk

        return(randomizedAnnouncement, proofResponse)
    

    def verifyNICKnonTransferable(self, randomizedGPrime, randomizedUpk, proof, ipar, randomizedCommitment, randomizedTag, disclosedSubset, subsetWitness):
        
        randomizedAnnouncement, proofResponse = proof

        challengeAnnouncement = (ipar, randomizedCommitment, randomizedTag, randomizedGPrime, randomizedUpk, disclosedSubset, subsetWitness, randomizedAnnouncement)
        challenge = self.hashForChallenge(challengeAnnouncement)

        left = randomizedGPrime ** proofResponse
        right = randomizedAnnouncement * randomizedUpk ** challenge

        return left == right

    def issueCred(self, disclosedAttributes, isk, ipar, upk):

        #get secret keys and ipar
        secretKeyMac, secretKeySetCommitment = isk
        x1, x2, x3 = secretKeyMac

        #sample random y
        y = self.group.random(self.scalarType)
        
        polynomial = self.evaluatePolynomial(disclosedAttributes, secretKeySetCommitment)

        commitment = (self.g1 ** (y * polynomial))

        #compute the tag tau
        tagTau = (commitment ** x1) * (self.gPrime ** x2) * (upk ** x3)

        #compute Yj(basis)
        basis = self.buildCommitmentBasis(secretKeySetCommitment, len(disclosedAttributes), y)

        #proof time :)
        pi = self.makeNIZK(secretKeyMac, secretKeySetCommitment, commitment, ipar, basis, tagTau, disclosedAttributes, upk)

        return tagTau, basis, pi
    

    def obtainCred(self, tagTau, basis, pi, disclosedAttributes, ipar, upk):

        # Compute polynomial
        coefficients = self.createPolynomial(disclosedAttributes)
        commitment = self.groupIdentity()
        
        for coeff, baseElement in zip(coefficients, basis):
            commitment = commitment * (baseElement ** coeff)

        #make sure commitment is not the basis element
        if commitment == self.groupIdentity():
                return None
        
        # verify zero knowledge and get check
        check = self.verifyNIZK(pi, commitment, ipar, basis, tagTau, disclosedAttributes, upk)
       
        #check that the challenge computed on user and issuer side are the same
        if check == False:
            return None
        
        return tagTau, basis, commitment
    

    def showCred(self, tagTau, basis, disclosedAttributes, requiredAttributeSubset, usk, upk, ipar, commitment):

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
        randomizedUpk = upk ** randomScalarMu
        randomizedGPrime = self.gPrime ** randomScalarMu
        randomizedCommitment = commitment ** randomScalarMu

        proof = self.makeNIZKnonTransferable(usk, randomizedGPrime, randomizedUpk, ipar, randomizedCommitment, randomizedTagTau, requiredAttributeSubset, witness)

        return randomizedTagTau, witness, proof, randomizedUpk, randomizedGPrime, randomizedCommitment
    

    def verify(self, randomizedTagTau, witness, requiredAttributeSubset, isk, randomizedCommitment, ipar, randomizedUpk, randomizedGPrime, proof):

        #Make sure that tag is not base element
        if randomizedTagTau == self.groupIdentity():
            return False
        
        #get keys
        secret_x, secret_v = isk
        secret_x1, secret_x2, secret_x3 = secret_x 

        # Hash attributes to ZR space and compute polynomail
        polynomial = self.evaluatePolynomial(requiredAttributeSubset, secret_v)

        # reconstruct proposed commitmnet
        validCommitment = witness ** polynomial
        
        # reconstruct proposed tag
        checkTag = (randomizedCommitment ** secret_x1) * (randomizedGPrime ** secret_x2) * (randomizedUpk ** secret_x3)

        nonTransferabilityProof = self.verifyNICKnonTransferable(randomizedGPrime, randomizedUpk, proof, ipar, randomizedCommitment, randomizedTagTau, requiredAttributeSubset, witness)

        return checkTag == randomizedTagTau and nonTransferabilityProof and validCommitment == randomizedCommitment