from charm.toolbox.pairinggroup import G1, G2, ZR
from DVSC_Scheme import DVSC
from SP_MAC_EQ_Scheme import SP_MAC_EQ



class KVAC_MEQ:
    """
    Extended KVAC-MEQ scheme with:
    - Added user public key binding (upk) into commitments and MAC computation
    - Extended SP-MAC-EQ secret key to (x1, x2, x3)
    - Added non-transferability (NICK-style proof) for credential presentation
    - Modified DVSC commitment representation to include public key randomness binding

    """

    def __init__(self, groupObject):
        """
        Extension:
        - Public parameters have additional gUpk 
        - pp is now := (G_1, G_2, G_T, p, e, g1, g2, g', g'', gUpk)
        - It's used in key generation by issuer to bind users public key to message.

        """
        
        self.group = groupObject
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.gPrime = self.group.random(G1)
        self.gPPrime = self.group.random(G1)
        self.gUpk = self.group.random(G1)

        self.SchemeDVSC = DVSC(self.group, self.g1, self.gPrime)
        self.SchemeMEQ = SP_MAC_EQ(self.group, self.g1, self.g2)


    def buildPIResponse(self, responseSequence, randomResponseSequence):
        """
        Extension:
        - SP-MAC-EQ secret key extended from (x1, x2) -> (x1, x2, x3)
        - Adds third response component sX3 for Fiat-Shamir proof consistency
        - Required due to inclusion of public key generator gUpk in MAC structure

        """

        #get needed variables
        randomScalar, challenge, tagRandom, x1, x2, x3 = responseSequence
        randomA, randomX1, randomX2, randomX3, randomR = randomResponseSequence

        #compute the different components of PI proof
        sA = (randomA) + (challenge * tagRandom)
        sX1 = randomX1 + (challenge * x1)
        sX2 = randomX2 + (challenge * x2)
        sX3 = randomX3 + (challenge * x3)
        sR = randomR + (challenge * randomScalar)

        return challenge, sA, sX1, sX2, sX3, sR
    

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


    def sigmaProtocol(self, randomScalar, x1, x2, x3, r, commitment, tagR):
        """
        Extension:
        - Sigma protocol now includes x3 and gUpk binding
        - Commitment structure extended:
            X = x1*g1 + x2*g' + x3*gUpk + r*g''
        - Ensures MAC consistency now includes user public key component
        """

        c1, c2, upk = commitment
        #compute X = x1 * G1 + x2 * G' + r * G''
        x = (x1 * self.g1) + (x2 * self.gPrime) + (x3 * self.gUpk) + (r * self.gPPrime)
        #T is the same as tag T
        t1 = randomScalar * self.g2
        #compute x1 * C1 + x2 * C2
        t2 = (x1 * c1) + (x2 * c2) + (x3 * upk) - (randomScalar * tagR)
        return x, t1, t2
    

    def makeNIZK(self, sk_MEQ, commitment, iparMEQ, tagR, tagT, disclosedAttributes, randomScalarR, randomScalarAInverse):
        """
        Extension:
        - Proof now includes additional witness x3 and corresponding randomness
        - Enables consistency proof over extended MAC key (x1, x2, x3)
        - Commitment now includes public key, making proof binding to user identity
        """
        #sample to get the needed variables
        randomProofAInverse = self.group.random(ZR)
        randomProofX1 = self.group.random(ZR)
        randomProofX2 = self.group.random(ZR)
        randomProofX3 = self.group.random(ZR)
        randomProofR = self.group.random(ZR)

        #Build sequence to give to sigma protocol (Ra, Rx1, Rx2, Rr, C, R)
        randomParameters = (randomProofAInverse, randomProofX1, randomProofX2, randomProofX3, randomProofR, commitment, tagR)

        #Compute the sigma protocol
        randomAnnouncement  = self.sigmaProtocol(*randomParameters)

        #Build sequence needed for the challenge (S, X, C, R, T, A)
        announcementSequence = (disclosedAttributes, iparMEQ, *commitment, tagR, tagT, randomAnnouncement)
        #Hash the sequence to get the challenge
        challenge = self.hashForChallenge(announcementSequence)

        #Make the two sequences that are needed to make the full Pi proof
        responseSequence = (randomScalarR, challenge, randomScalarAInverse, *sk_MEQ)
        randomResponseSequence = (randomProofAInverse, randomProofX1, randomProofX2, randomProofX3, randomProofR)
        
        #Build the final PI response as the proof
        finalProof = self.buildPIResponse(responseSequence, randomResponseSequence)

        return finalProof

        
    def verifyNIZK(self, proofChallenge, proofSA, proofSX1, proofSX2, proofSX3, proofSR, commitment, disclosedAttributes, tagR, tagT, iparMEQ):

        #Compute the first part for verifying the PI proof
        sigmaX, sigmaT1, sigmaT2 = self.sigmaProtocol(proofSA, proofSX1, proofSX2, proofSX3, proofSR, commitment, tagR)
    
        # unique accepting Sigma protocol announcement (UASPA)
        iparMEQ_UASPA = sigmaX - proofChallenge * iparMEQ
        tagT_UASPA = sigmaT1 - proofChallenge * tagT
        zero_UASPA = sigmaT2

        #make the sequence that is needed for the new challenge
        verifyChallengeAnnouncementSeq = (disclosedAttributes, iparMEQ, *commitment, tagR, tagT, (iparMEQ_UASPA, tagT_UASPA, zero_UASPA))

        #hash the sequence
        newChallenge = self.hashForChallenge(verifyChallengeAnnouncementSeq)

        #check that the new challenge is the same as the challenge computed on the issuer side
        return proofChallenge == newChallenge

    def makeNIZKnonTransferable(self, usk, randomizedGPrime, randomizedUpk, ipar, randomizedCommitment, randomizedTag, disclosedSubset, subsetWitness):
        """
        Non-transferability proof (NIZK-style construction)

        Purpose:
        - Proves possession of secret user key (usk)
        - Binds credential presentation to a specific user public key
        - Prevents credential sharing between users

        Construction:
        - Fiat-Shamir proof of knowledge of usk
        - Uses randomized commitment and tag context
        """
        randomizer = self.group.random(ZR)
        randomizedAnnouncement = randomizer * randomizedGPrime

        challengeAnnouncement = (ipar, randomizedCommitment, randomizedTag, randomizedUpk, disclosedSubset, subsetWitness, randomizedAnnouncement)
        challenge = self.hashForChallenge(challengeAnnouncement)
        
        proofResponse = randomizer + challenge * usk

        return(randomizedAnnouncement, proofResponse)
    

    def verifyNIZKnonTransferable(self, randomizedGPrime, randomizedUpk, proof, ipar, randomizedCommitment, randomizedTag, disclosedSubset, subsetWitness):
        """
        Extension:
        - Verifies Schnorr-style proof of knowledge of user secret key
        - Ensures presentation is bound to randomizedUpk and randomizedGPrime
        """
        randomizedAnnouncement, proofResponse = proof

        challengeAnnouncement = (ipar, randomizedCommitment, randomizedTag, randomizedUpk, disclosedSubset, subsetWitness, randomizedAnnouncement)
        challenge = self.hashForChallenge(challengeAnnouncement)

        left = randomizedGPrime * proofResponse
        right = randomizedAnnouncement + randomizedUpk * challenge

        return left == right
    

    def keyGen(self, attributeListSize):
        """
        Extension:
        - MAC key extended to 3 components (x1, x2, x3)
        - Public key generator gUpk introduced into system
        - iparMEQ now binds credentials to user public key space
        """

        #make the secret key from MEQ scheme upperbound of 2
        sk_MEQ = self.SchemeMEQ.keyGen(3)

        #get the ipar and secret key from DVSC scheme
        sk_DVSC, challenge, response, commitmentBasis = self.SchemeDVSC.keyGen(attributeListSize)
        iparDVSC = (challenge, response, commitmentBasis)

        #compute the MEQ ipar as stated in the book
        randomScalarR = self.group.random(ZR)
        iparMEQ = (sk_MEQ[0] * self.g1) + (sk_MEQ[1] * self.gPrime) + (sk_MEQ[2] * self.gUpk) + (randomScalarR * self.gPPrime)

        isk = (sk_MEQ, sk_DVSC, randomScalarR)
        ipar = (iparMEQ, iparDVSC)
        
        return isk, ipar, self.gPrime
    

    def issueCred(self, disclosedAttributes, isk, commitmentBasis, iparMEQ, upk):
        """
        Extension:
        - Commitment is augmented with user public key (upk)
        - MAC tag is now computed over (commitment, upk)
        - Ensures credential is bound to a specific user identity
        """
        #parse the secret keys and ipar
        sk_MEQ, _, randomScalarR  = isk

        #compute the commitment from the DVSC scheme and serialize it so createMac can iterate over
        commitment = self.SchemeDVSC.commit(commitmentBasis, disclosedAttributes)

        #check commitment is valid
        if commitment is None:
            return None

        #get the random scalar A and make it inverse
        randomScalarA = self.group.random(ZR)
        randomScalarAInverse = randomScalarA ** -1

        #add public key to be sent to MAC
        commitmentList = list(commitment)
        commitmentList.append(upk)
        #compute the tag from the MEQ scheme
        tagR, tagT = self.SchemeMEQ.createMac(sk_MEQ, commitmentList, randomScalarA)
      
        # Proof time :)
        proof = self.makeNIZK(sk_MEQ, commitmentList, iparMEQ, tagR, tagT, disclosedAttributes, randomScalarR, randomScalarAInverse)

        return tagR, tagT, proof, commitmentList, commitment
    
    
    def obtainCred(self, disclosedAttributes, iparDVSC, iparMEQ, proof, tagR, tagT, upk, checkIssuerParamater=False):
        """
        Extension:
        - Verification ensures MAC tag consistency with upk binding
        - Prevents credential reuse with different public keys
        """

        #get needed variables
        proofChallenge, proofSA, proofSX1, proofSX2, proofSX3, proofSR = proof
        challenge, response, commitmentBasis = iparDVSC

        if checkIssuerParamater:
            if not self.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis):
                print('1')
                return None

        #make commitment
        commitment = self.SchemeDVSC.commit(commitmentBasis, disclosedAttributes)

        #check that iparDVSC is valid
        if commitment is None:
            print('2')
            return None
        commitmentList = list(commitment)
        commitmentList.append(upk)
        # Proof time :)
        check = self.verifyNIZK(proofChallenge, proofSA, proofSX1, proofSX2, proofSX3, proofSR, commitmentList, disclosedAttributes, tagR, tagT, iparMEQ)

        if check == False:
            print('3')
            return None
        
        return tagR, tagT
    

    def showCred(self, tagR, tagT, disclosedAttributes, requiredAttributesSubset, encodedMessages, ipar, upk, usk):
        """
        Extension:
        - Adds non-transferability layer via proof of secret key possession
        - Randomized presentation now binds:
            - commitment
            - MAC tag
            - user public key
        - Ensures credential cannot be replayed by another user
        """
        #get random scalar
        randomScalarMu = self.group.random(ZR)
        while randomScalarMu == self.group.init(ZR):
            randomScalarMu = self.group.random(ZR)

        _, iparDVSC = ipar
        _,_, commitmentBasis = iparDVSC

        #compute the randomized tag
        randomizedTag = self.SchemeMEQ.changeRepresentation(encodedMessages, tagR, tagT, randomScalarMu)

        #make a commitment
        commitment = self.SchemeDVSC.commit(commitmentBasis, disclosedAttributes)
        #compute randomized commitment
        randomC1, randomC2, randomizedUpk, randomizedGPrime = self.SchemeDVSC.randomize(*commitment, randomScalarMu, upk, self.gPrime)

        randomizedCommitment = (randomC1, randomC2, randomizedUpk, randomizedGPrime)

        #compute witness
        witness = self.SchemeDVSC.openSubset(commitmentBasis, disclosedAttributes, requiredAttributesSubset, randomScalarMu)

        proof = self.makeNIZKnonTransferable(usk, randomizedGPrime, randomizedUpk, ipar, randomizedCommitment, randomizedTag, requiredAttributesSubset, witness)

        return randomizedTag, randomizedCommitment, witness, proof


    def verify(self, randomizedTag, randomizedCommitment, witness, requiredAttributesSubset, isk, proof, ipar):
        """
        Extension:
        - Verification now includes:
            - SP-MAC-EQ verification
            - DVSC subset verification
            - Non-transferability proof verification
        """
        sk_MEQ, sk_DVSC, _ = isk
        changedMessages, tagR, tagT = randomizedTag

        randomC1, _, randomizedUpk, randomizedGPrime = randomizedCommitment

        #use functions from other two scheme to verify the subset and commtiment
        verifyMEQ = self.SchemeMEQ.verify(sk_MEQ, changedMessages, tagR, tagT)
        verifySubset = self.SchemeDVSC.verifySubset(
            sk_DVSC, randomC1, witness, requiredAttributesSubset
        )

        #make sure secret key is valid
        validSecretKey = self.verifyNIZKnonTransferable(randomizedGPrime, randomizedUpk, proof, ipar, randomizedCommitment, randomizedTag, requiredAttributesSubset, witness)

        return verifyMEQ and verifySubset and validSecretKey

