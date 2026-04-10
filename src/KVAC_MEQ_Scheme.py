from charm.toolbox.pairinggroup import G1, G2, ZR
from DVSC_Scheme import DVSC
from SP_MAC_EQ_Scheme import SP_MAC_EQ



class KVAC_MEQ:

    def __init__(self, groupObject):
        
        self.group = groupObject
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.gPrime = self.group.random(G1)
        self.gPPrime = self.group.random(G1)

        self.Scheme_DVSC = DVSC(self.group, self.g1, self.gPrime)
        self.Scheme_MEQ = SP_MAC_EQ(self.group, self.g1, self.g2)

    def buildPIResponse(self, responseSequence, randomResponseSequence):

        #get needed variables
        randomScalar, challenge, tagRandom, x1, x2 = responseSequence
        randomA, randomX1, randomX2, randomR = randomResponseSequence

        #compute the different components of PI proof
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
        #compute X = x1 * G1 + x2 * G' + r * G''
        x = (x1 * self.g1) + (x2 * self.gPrime) + (r * self.gPPrime)
        #T is the same as tag T
        t1 = randomScalar * self.g2
        #compute x1 * C1 + x2 * C2
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
        ipar_MEQ = (sk_MEQ[0] * self.g1) + (sk_MEQ[1] * self.gPrime) + (randomSaclarR * self.gPPrime)

        isk = (sk_MEQ, sk_DVSC, randomSaclarR)
        ipar = (ipar_MEQ, ipar_DVSC)
        return isk, ipar
    
    def issueCred(self, attributesRaw, isk, ipar_DVSC, ipar_MEQ):

        #parse the secret keys and ipar
        sk_MEQ, _, randomSaclarR  = isk
        challenge, response, commitmentBasis = ipar_DVSC

        #compute the commitment from the DVSC scheme and serialize it so createMac can iterate over
        commitment = self.Scheme_DVSC.commit(challenge, response, commitmentBasis, attributesRaw)

        #check commitment is valid
        if commitment is None:
            return None

        #get the random scalar A and make it inverse
        randomScalarA = self.group.random(ZR)
        randomScalarAInverse = randomScalarA ** -1

        
        #compute the tag from the MEQ scheme
        encodedMessages, tagR, tagT = self.Scheme_MEQ.createMac(sk_MEQ, list(commitment), randomScalarA)
      
        # Proof time :)
        #sample to get the needed variables
        randomAInverseProof = self.group.random(ZR)
        randomX1 = self.group.random(ZR)
        randomX2= self.group.random(ZR)
        randomR = self.group.random(ZR)

        #Build sequence to give to sigma protocol (Ra, Rx1, Rx2, Rr, C, R)
        randomParameters = (randomAInverseProof, randomX1, randomX2, randomR, commitment, tagR)

        #Compute the sigma protocol
        randomAnnouncement  = self.sigmaProtocol(*randomParameters)

        #Build sequence needed for the challenge (S, X, C, R, T, A)
        announcementSequence = (attributesRaw, ipar_MEQ, *commitment, tagR, tagT, randomAnnouncement)

        #Hash the sequence to get the challenge
        challenge = self.hashForChallenge(announcementSequence)

        #Make the two sequences that are needed to make the full Pi proof
        responseSequence = (randomSaclarR, challenge, randomScalarAInverse, *sk_MEQ)
        randomResponseSequence = (randomAInverseProof, randomX1, randomX2, randomR)

        #Build the final PI response
        response = self.buildPIResponse(responseSequence, randomResponseSequence)

        return tagR, tagT, response, encodedMessages, commitment
    
    
    def obtainCred(self, attributesRaw, ipar_DVSC, ipar_MEQ, response, tagR, tagT):

        #get needed variables
        responseChallenge, responseSA, responseSX1, reponseSX2, responseSR = response

        #make commitment
        commitment = self.Scheme_DVSC.commit(*ipar_DVSC, attributesRaw)

        #check that ipar_dvsc is valid
        if commitment is None:
            return None

        #Compute the first part for verifying the PI proof
        sigmaX, sigmaT1, sigmaT2 = self.sigmaProtocol(responseSA, responseSX1, reponseSX2, responseSR, commitment, tagR)
    
        # unique accepting Sigma protocol announcement (UASPA)
        ipar_MEQ_UASPA = sigmaX - responseChallenge * ipar_MEQ
        tagT_UASPA = sigmaT1 - responseChallenge * tagT
        zero_UASPA = sigmaT2

        #make the sequence that is needed for the new challenge
        verifyChallengeAnnouncementSeq = (attributesRaw, ipar_MEQ, *commitment, tagR, tagT, (ipar_MEQ_UASPA, tagT_UASPA, zero_UASPA))

        #hash the sequence
        newChallenge = self.hashForChallenge(verifyChallengeAnnouncementSeq)

        #check that the new challenge is the same as the challenge computed on the issuer side
        if responseChallenge != newChallenge:
            return None
        
        return tagR, tagT
    

    def showCred(self, tagR, tagT, attributesRaw, subset, encodedMessages, ipar_DVSC):
        #get random scalar
        mu = self.group.random(ZR)

        _,_, commitmentBasis = ipar_DVSC

        #compute the randomized tag
        randomizedTag = self.Scheme_MEQ.changeRepresentation(encodedMessages, tagR, tagT, mu)

        #make a commitment
        commitment = self.Scheme_DVSC.commit(*ipar_DVSC, attributesRaw)
        #compute randomized commitment
        ranomizedCommitment = self.Scheme_DVSC.randomize(*commitment, mu)

        #compute witness
        witness = self.Scheme_DVSC.openSubset(commitmentBasis, attributesRaw, subset, mu)

        return randomizedTag, ranomizedCommitment, witness


    def verify(self, randomizedTag, randomizedCommitment, witness, subset, isk):

        sk_MEQ, sk_DVSC, _ = isk
        changedMessages, tagR, tagT = randomizedTag

        #use functions from other two scheme to verify the subset and commtiment
        verifyMEQ = self.Scheme_MEQ.verify(sk_MEQ, changedMessages, tagR, tagT)
        verifySubset = self.Scheme_DVSC.verifySubset(
            sk_DVSC, randomizedCommitment[0], witness, subset
        )

        return verifyMEQ and verifySubset



    







    








        




