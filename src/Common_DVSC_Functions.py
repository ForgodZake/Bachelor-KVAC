from charm.toolbox.pairinggroup import G1, ZR as PAIRING_ZR
from charm.toolbox.ecgroup import G, ZR as EC_ZR


class Common_DVSC_Functions:

    def __init__(self, groupObject, generator):
        
        self.group = groupObject
        self.groupSetting = self.group.groupSetting()
        self.g1 = generator

        if self.groupSetting == "ellipctic_curve":
            self.groupElementType = G
            self.scalarType = EC_ZR
        else:
            self.groupElementType = G1
            self.scalarType = PAIRING_ZR

    def groupIdentity(self):
        return self.group.init(self.groupElementType)
    
    def scalarZero(self):
        return self.group.init(self.scalarType)

    def scalarOne(self):
        return self.group.init(self.scalarType, 1) 

    def createPolynomial(self, disclosedAttributes):
        
        coefficients = [1]

        # for each attribute we update the polynomial degree,
        # by doing currentPoly * (X - a)
        for attribute in disclosedAttributes:
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
        result = self.scalarZero()
        power = self.scalarOne()

        # compute the output of the polynomial with secretKey as input 
        for coefficient in coefficients:
            result += coefficient * power
            power *= secretKey

        return result
    
    def evaluatePolynomialForVerification(self, attributesRaw, secretKey):
        result = self.scalarOne()

        for attribute in attributesRaw:
            hashedAttributes = self.group.hash(attribute, self.scalarType)
            result *= (secretKey - hashedAttributes)

        return result
        
    
    def openSubset(self, commitmentBasis, attributesRaw, requiredAttributeSubsetRaw, randomScalarMu):

        remainingAttributesRaw = []
        # Create the set without the subset (S / D)
        for i in range(len(attributesRaw)):
            if not (attributesRaw[i] in requiredAttributeSubsetRaw):
                remainingAttributesRaw.append(attributesRaw[i])

        # Hash the remaining attributes (needed as they are strings) and create the polynomial
        disclosedRemainingAttributes = [self.group.hash(attributeRaw, self.scalarType) for attributeRaw in remainingAttributesRaw]
        coefficients = self.createPolynomial(disclosedRemainingAttributes)

        # Create the witness by scaling the commitment with our random mu
        witness = randomScalarMu * self.createCommitment(coefficients, commitmentBasis)

        return witness
    
    def createCommitment(self, coefficients, commitmentBasis):

        commitment = self.groupIdentity()

        # create commitment by scaling each basis element by the coefficient (f_i * V_i)
        for i in range(len(coefficients)):
            commitment += coefficients[i] * commitmentBasis[i]

        return commitment
    
    def hashForChallenge(self, announcementSequence):

        # convert announcement to byterepresentation for hashing
        byteRepresentation = self.toBytes(announcementSequence)

        return self.group.hash(byteRepresentation, self.scalarType)
    
    def toBytes(self, announcementSequence):

        # If announcementSequence is string encode 
        if isinstance(announcementSequence, str):
            return announcementSequence.encode("utf-8")

        # If announcementSequence is list or tuble recursively access each element,
        # and concatenate encoding/serialization to result.
        if isinstance(announcementSequence, (list, tuple)):
            parts = []
            for item in announcementSequence:
                parts.append(self.toBytes(item))
            return b"||".join(parts)

        # Otherwise serialize elements from group objects (G1, G2, ZR elements)
        return self.group.serialize(announcementSequence)
    