from charm.toolbox.pairinggroup import G1, ZR

class KVAC_GGM:

    def __init__(self, groupObject):

        self.group = groupObject
        self.G = self.group.random(G1)

    def keyGen(self):

        generator = self.G

        x = self.group.random(ZR)
        v = self.group.random(ZR)
        r = self.group.random(ZR)

        #make the secret key
        secretKey = x, v

        #compute the public parameters
        ipar_R = r * generator
        ipar_X = r * x * generator
        ipar_v = v * generator

        ipar = ipar_R, ipar_X, ipar_v

        return secretKey, ipar
    
    def buildCommitmentBasis(self, secretKey, upperBound, y):

        basisElement = y * self.G
        commitmentBasis = [basisElement]

        for i in range(upperBound):
            basisElement *= secretKey

            commitmentBasis.append(basisElement)
        #return commitment basis
        return commitmentBasis
    
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
    
    def evaluatePolynomial(self, coefficients, secretKey):
        
        result = self.group.init(ZR, 0)
        power = 1

        # compute the output of the polynomial with secretKey as input 
        for coefficient in coefficients:
            result += coefficient * power
            power *= secretKey

        return result
    
    def sigmaProtocol(self, commitment, ipar_R, basis, x, v):
        sigma_C = x * commitment
        sigma_R = x * ipar_R
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

    
    def issueCred(self, attributesRaw, isk, ipar):
        #get secret keys
        secret_x, secret_v = isk

        ipar_R, ipar_X, ipar_v = ipar

        y = self.group.random(ZR)

        # Hash attributes to ZR space
        attributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]
        coefficents = self.createPolynomial(attributes)
        polynomial = self.evaluatePolynomial(coefficents, secret_v)
        commitment = (y * polynomial * self.G)

        tag = secret_x * commitment

        basis = self.buildCommitmentBasis(secret_v, len(attributesRaw), y)

        #proof time :)
        random_x = self.group.random(ZR)
        random_v = self.group.random(ZR)

        announcement = self.sigmaProtocol(commitment, ipar_R, basis, random_x, random_v)

        hashSequence = (attributesRaw, tag, ipar_v, commitment, ipar_X, ipar_R, basis, announcement)

        challenge = self.hashForChallenge(hashSequence)

        response_x, response_v = self.buildPIResponse(random_x, random_v, challenge, secret_x, secret_v)

        pi = (challenge, response_x, response_v)

        return tag, basis, pi
    

    def obtainCred(self, tag, basis, pi, attributesRaw, ipar):
        challenge, response_x, response_v = pi
        
        ipar_R, ipar_X, ipar_v = ipar

        # Hash attributes to ZR space
        attributes = [self.group.hash(attribute, ZR) for attribute in attributesRaw]

        coefficients = self.createPolynomial(attributes)
        commitment = self.group.init(G1)

        for coeff, baseElement in zip(coefficients, basis):
            commitment += coeff * baseElement


        if commitment == self.group.init(G1):
                return None
        
        sigmaAnnouncement_C, sigmaAnnouncement_R, sigmaAnnouncement_basis = self.sigmaProtocol(commitment, ipar_R, basis, response_x, response_v)

        announcement_tag = sigmaAnnouncement_C - (challenge * tag)
        announcement_X = sigmaAnnouncement_R - (challenge * ipar_X)
        announcement_basis = []

        for i in range(len(basis)-1):
            announcement_basis.append(sigmaAnnouncement_basis[i] - (challenge * basis[i+1]))

        announcement = (announcement_tag, announcement_X, announcement_basis)

        userChallenge = (attributesRaw, tag, ipar_v, commitment, ipar_X, ipar_R, basis, announcement)

        userChallengeHash = self.hashForChallenge(userChallenge)

        if challenge != userChallengeHash:
        
            return None
        
        return tag, basis
    
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
    
    def createCommitment(self, coefficients, commitmentBasis):

        commitment = self.group.init(G1)

        # create commitment by scaling each basis element by the coefficient (f_i * V_i)
        for i in range(len(coefficients)):
            commitment += coefficients[i] * commitmentBasis[i]

        return commitment
    

    def showCred(self, tag, basis, attributesRaw, subset):

        randomMu = self.group.random(ZR)
        while randomMu == self.group.init(ZR):
            randomMu = self.group.random(ZR)

        if subset
        witness = self.openSubset(basis, attributesRaw, subset, randomMu)

        randomizedTag = randomMu * tag

        return randomizedTag, witness
    

    def verify(self, randomizedTag, witness, subset, isk):


        if randomizedTag == self.group.init(G1):
            return False
        x, v = isk

        # Hash attributes to ZR space
        attributes = [self.group.hash(attribute, ZR) for attribute in subset]

        coefficients = self.createPolynomial(attributes)
        polynomial = self.evaluatePolynomial(coefficients, v)

        check = x * witness * polynomial

        if check == randomizedTag:
            return True
        
        return False