from charm.toolbox.pairinggroup import G1, ZR

class PolyCommitBase:

    def __init__(self, groupObject, generator):
        
        self.group = groupObject
        self.g1 = generator

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
        
        result = self.group.init(ZR)
        power = 1

        # compute the output of the polynomial with secretKey as input 
        for coefficient in coefficients:
            result += coefficient * power
            power *= secretKey

        return result
    
    def openSubset(self, commitmentBasis, attributesRaw, requiredAttributeSubsetRaw, randomScalarMu):

        remainingAttributesRaw = []
        # Create the set without the subset (S / D)
        for i in range(len(attributesRaw)):
            if not (attributesRaw[i] in requiredAttributeSubsetRaw):
                remainingAttributesRaw.append(attributesRaw[i])

        # Hash the remaining attributes (needed as they are strings) and create the polynomial
        disclosedRemainingAttributes = [self.group.hash(attributeRaw, ZR) for attributeRaw in remainingAttributesRaw]
        coefficients = self.createPolynomial(disclosedRemainingAttributes)

        # Create the witness by scaling the commitment with our random mu
        witness = randomScalarMu * self.createCommitment(coefficients, commitmentBasis)

        return witness
    
    def createCommitment(self, coefficients, commitmentBasis):

        commitment = self.group.init(G1)

        # create commitment by scaling each basis element by the coefficient (f_i * V_i)
        for i in range(len(coefficients)):
            commitment += coefficients[i] * commitmentBasis[i]

        return commitment