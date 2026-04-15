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

        self.SchemeDVSC = DVSC(self.group, self.g1, self.gPrime)
        self.SchemeMEQ = SP_MAC_EQ(self.group, self.g1, self.g2)

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
            parts = []
            for item in announcementSequence:
                parts.append(self.toBytes(item))
            return b"||".join(parts)

        # Otherwise serialize elements from group objects (G1, G2, ZR elements)
        return self.group.serialize(announcementSequence)


    def sigmaProtocol(self, randomScalar, x1, x2, r, commitment, tagR):

        c1, c2 = commitment
        #compute X = x1 * G1 + x2 * G' + r * G''
        x = (x1 * self.g1) + (x2 * self.gPrime) + (r * self.gPPrime)
        #T is the same as tag T
        t1 = randomScalar * self.g2
        #compute x1 * C1 + x2 * C2
        t2 = (x1 * c1) + (x2 * c2) - (randomScalar * tagR)
        return x, t1, t2
    

    def makeNIZK(self, sk_MEQ, commitment, iparMEQ, tagR, tagT, attributesRaw, randomScalarR, randomScalarAInverse):

        #sample to get the needed variables
        randomProofAInverse = self.group.random(ZR)
        randomProofX1 = self.group.random(ZR)
        randomProofX2= self.group.random(ZR)
        randomProofR = self.group.random(ZR)

        #Build sequence to give to sigma protocol (Ra, Rx1, Rx2, Rr, C, R)
        randomParameters = (randomProofAInverse, randomProofX1, randomProofX2, randomProofR, commitment, tagR)

        #Compute the sigma protocol
        randomAnnouncement  = self.sigmaProtocol(*randomParameters)

        #Build sequence needed for the challenge (S, X, C, R, T, A)
        announcementSequence = (attributesRaw, iparMEQ, *commitment, tagR, tagT, randomAnnouncement)
        #Hash the sequence to get the challenge
        challenge = self.hashForChallenge(announcementSequence)

        #Make the two sequences that are needed to make the full Pi proof
        responseSequence = (randomScalarR, challenge, randomScalarAInverse, *sk_MEQ)
        randomResponseSequence = (randomProofAInverse, randomProofX1, randomProofX2, randomProofR)
        
        #Build the final PI response as the proof
        finalProof = self.buildPIResponse(responseSequence, randomResponseSequence)

        return finalProof

        
    def verifyNIZK(self, proofChallenge, proofSA, proofSX1, proofSX2, proofSR, commitment, attributesRaw, tagR, tagT, iparMEQ):

        #Compute the first part for verifying the PI proof
        sigmaX, sigmaT1, sigmaT2 = self.sigmaProtocol(proofSA, proofSX1, proofSX2, proofSR, commitment, tagR)
    
        # unique accepting Sigma protocol announcement (UASPA)
        iparMEQ_UASPA = sigmaX - proofChallenge * iparMEQ
        tagT_UASPA = sigmaT1 - proofChallenge * tagT
        zero_UASPA = sigmaT2

        #make the sequence that is needed for the new challenge
        verifyChallengeAnnouncementSeq = (attributesRaw, iparMEQ, *commitment, tagR, tagT, (iparMEQ_UASPA, tagT_UASPA, zero_UASPA))

        #hash the sequence
        newChallenge = self.hashForChallenge(verifyChallengeAnnouncementSeq)

        #check that the new challenge is the same as the challenge computed on the issuer side
        if proofChallenge != newChallenge:
            return False

        return True

    def keyGen(self, attributeListSize):
        #make the secret key from MEQ scheme upperbound of 2
        sk_MEQ = self.SchemeMEQ.keyGen(2)

        #get the ipar and secret key from DVSC scheme
        sk_DVSC, challenge, response, commitmentBasis = self.SchemeDVSC.keyGen(attributeListSize)
        iparDVSC = (challenge, response, commitmentBasis)

        #compute the MEQ ipar as stated in the book
        randomScalarR = self.group.random(ZR)
        iparMEQ = (sk_MEQ[0] * self.g1) + (sk_MEQ[1] * self.gPrime) + (randomScalarR * self.gPPrime)

        isk = (sk_MEQ, sk_DVSC, randomScalarR)
        ipar = (iparMEQ, iparDVSC)
        return isk, ipar
    
    def issueCred(self, attributesRaw, isk, iparDVSC, iparMEQ):

        #parse the secret keys and ipar
        sk_MEQ, _, randomScalarR  = isk
        _, _, commitmentBasis = iparDVSC

        #compute the commitment from the DVSC scheme and serialize it so createMac can iterate over
        commitment = self.SchemeDVSC.commit(commitmentBasis, attributesRaw)

        #check commitment is valid
        if commitment is None:
            return None

        #get the random scalar A and make it inverse
        randomScalarA = self.group.random(ZR)
        randomScalarAInverse = randomScalarA ** -1

        #compute the tag from the MEQ scheme
        encodedMessages, tagR, tagT = self.SchemeMEQ.createMac(sk_MEQ, list(commitment), randomScalarA)
      
        # Proof time :)
        proof = self.makeNIZK(sk_MEQ, commitment, iparMEQ, tagR, tagT, attributesRaw, randomScalarR, randomScalarAInverse)

        return tagR, tagT, proof, encodedMessages, commitment
    
    
    def obtainCred(self, attributesRaw, iparDVSC, iparMEQ, proof, tagR, tagT, checkIssuerParamater=False):

        #get needed variables
        proofChallenge, proofSA, proofSX1, proofSX2, proofSR = proof
        challenge, response, commitmentBasis = iparDVSC

        if checkIssuerParamater:
            if not self.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis):
                return None

        #make commitment
        commitment = self.SchemeDVSC.commit(commitmentBasis, attributesRaw)

        #check that iparDVSC is valid
        if commitment is None:
            return None

        # Proof time :)
        check = self.verifyNIZK(proofChallenge, proofSA, proofSX1, proofSX2, proofSR, commitment, attributesRaw, tagR, tagT, iparMEQ)

        if check == False:
            return None
        
        return tagR, tagT
    

    def showCred(self, tagR, tagT, attributesRaw, requiredAttributesSubsetRaw, encodedMessages, iparDVSC):
        
        #get random scalar
        randomScalarMu = self.group.random(ZR)
        while randomScalarMu == self.group.init(ZR):
            randomScalarMu = self.group.random(ZR)

        _,_, commitmentBasis = iparDVSC

        #compute the randomized tag
        randomizedTag = self.SchemeMEQ.changeRepresentation(encodedMessages, tagR, tagT, randomScalarMu)

        #make a commitment
        commitment = self.SchemeDVSC.commit(commitmentBasis, attributesRaw)
        #compute randomized commitment
        ranomizedCommitment = self.SchemeDVSC.randomize(*commitment, randomScalarMu)

        #compute witness
        witness = self.SchemeDVSC.openSubset(commitmentBasis, attributesRaw, requiredAttributesSubsetRaw, randomScalarMu)

        return randomizedTag, ranomizedCommitment, witness


    def verify(self, randomizedTag, randomizedCommitment, witness, requiredAttributesSubsetRaw, isk):

        sk_MEQ, sk_DVSC, _ = isk
        changedMessages, tagR, tagT = randomizedTag

        #use functions from other two scheme to verify the subset and commtiment
        verifyMEQ = self.SchemeMEQ.verify(sk_MEQ, changedMessages, tagR, tagT)
        verifySubset = self.SchemeDVSC.verifySubset(
            sk_DVSC, randomizedCommitment[0], witness, requiredAttributesSubsetRaw
        )

        return verifyMEQ and verifySubset



    







    








        




