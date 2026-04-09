from charm.toolbox.pairinggroup import G1, G2, ZR
from DVSC_Scheme import DVSC
from SP_MAC_EQ_Scheme import SP_MAC_EQ



class KVAC_MEQ:

    def __init__(self, groupObject):
        
        self.group = groupObject
        self.G1 = self.group.random(G1)
        self.G2 = self.group.random(G2)
        self.Gprime = self.group.random(G1)
        self.Gpprime = self.group.random(G1)

        self.Scheme_DVSC = DVSC(self.group)
        self.Scheme_MEQ = SP_MAC_EQ(self.group)

    def buildResponse(self, responseSequence, randomResponseSequence):
        randomScalar, challenge, tagRandom, x1, x2 = responseSequence
        randomA, randomX1, randomX2, randomR = randomResponseSequence

        sA = (randomA) + (challenge * tagRandom)
        sX1 = randomX1 + (challenge * x1)
        sX2 = randomX2 + (challenge * x2)
        sR = randomR + (challenge * randomScalar)

        return challenge, sA, sX1, sX2, sR
    
    # fix this shit!!!!!!!!!!!!!!!!!!!!!!!
    def hashForChallenge(self, obj):
        byteRepresentation = self._toBytes(obj)
        return self.group.hash(byteRepresentation, ZR)

    def _toBytes(self, obj):
        if isinstance(obj, str):
            return obj.encode("utf-8")

        if isinstance(obj, (list, tuple)):
            result = b""
            for item in obj:
                result += self._toBytes(item)
            return result

        return self.group.serialize(obj)

    

    def sigmaProtocol(self, randomScalar, x1, x2, r, commitment, tagR):
        c1, c2 = commitment
        x = (x1 * self.G1) + (x2 * self.Gprime) + (r * self.Gpprime)
        t1 = randomScalar * self.G2
        t2 = (x1 * c1) + (x2 * c2) - (randomScalar * tagR)
        return x, t1, t2

    def keyGen(self, attributeListSize):
        #make the secret key from MEQ scheme upperbound of 2
        sk_MEQ = self.Scheme_MEQ.keyGen(2)

        #get the ipar and secret key from DVSC scheme
        sk_DVSC, challenge, response, commitmentBasis = self.Scheme_DVSC.keyGen(attributeListSize)
        ipar_DVSC = (challenge, response, commitmentBasis)

        #compute the MEQ ipar as stated in the book
        randomSaclarR = self.group.random(ZR)
        ipar_MEQ = (sk_MEQ[0] * self.G1) + (sk_MEQ[1] * self.Gprime) + (randomSaclarR * self.Gpprime)

        isk = (sk_MEQ, sk_DVSC, randomSaclarR)
        ipar = (ipar_MEQ, ipar_DVSC)
        return isk, ipar
    
    def issueCred(self, attributesRaw, isk, ipar_DVSC):

        #parse the secret keys and ipar
        sk_MEQ, _, randomSaclarR  = isk
        challenge, response, commitmentBasis = ipar_DVSC

        #compute the commitment from the DVSC scheme and serialize it so createMac can iterate over
        commitment = self.Scheme_DVSC.commit(challenge, response, commitmentBasis, attributesRaw)

        randomScalarA = self.group.random(ZR)

        #compute the tag from the MEQ scheme
        encodedMessages, tagR, tagT = self.Scheme_MEQ.createMac(sk_MEQ, commitment, randomScalarA)

      
        # Proof time :)
        x, t1, t2 = self.sigmaProtocol(randomScalarA, *sk_MEQ, randomSaclarR, commitment, tagR)

    
        randomA = self.group.random(ZR)
        randomX1 = self.group.random(ZR)
        randomX2= self.group.random(ZR)
        randomR = self.group.random(ZR)

        randomParameters = (randomX1, randomX2, randomR, commitment, tagR)

        randomAnnouncement  = self.sigmaProtocol(randomA, *randomParameters)

        announcementSequence = (attributesRaw, x, commitment, tagR, t1, t2, *randomAnnouncement)

        challenge = self.hashForChallenge(announcementSequence)

        responseSequence = (randomSaclarR, challenge, randomScalarA, *sk_MEQ)

        randomResponseSequence = (randomA, randomX1, randomX2, randomR)

        response = self.buildResponse(responseSequence, randomResponseSequence)

        return tagR, tagT, response, encodedMessages, commitment
    
    
    def obtainCred(self, attributesRaw, ipar_DVSC):

        commitment = self.Scheme_DVSC.commit(*ipar_DVSC, attributesRaw)

        if commitment is None:
            return None
        
        return commitment
    

    def showCred(self, tagR, tagT, attributesRaw, subset, encodedMessages, commitmentBasis, commitment):

        mu = self.group.random(ZR)


        randomizedTag = self.Scheme_MEQ.changeRepresentation(encodedMessages, tagR, tagT, mu)

        ranomizedCommitment = self.Scheme_DVSC.randomize(*commitment, mu)

        witness = self.Scheme_DVSC.openSubset(commitmentBasis, attributesRaw, subset, mu)

        return randomizedTag, ranomizedCommitment, witness
    
    
    def verify(self, randomizedTag, randomizedCommitment, witness, subset, isk):

        sk_MEQ, sk_DVSC, _ = isk
        _, tagR, tagT = randomizedTag

        verifyMEQ = self.Scheme_MEQ.verify(sk_MEQ, randomizedCommitment, tagR, tagT)

        verifySubset = self.Scheme_DVSC.verifySubset(sk_DVSC, randomizedCommitment, witness, subset)

        return True if verifySubset == True and verifyMEQ == True else False



    







    








        




