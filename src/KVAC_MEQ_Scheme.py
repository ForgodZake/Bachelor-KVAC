from charm.toolbox.pairinggroup import G1, G2, ZR
from DVSC_Scheme import DVSC
from SP_MAC_EQ_Scheme import SP_MAC_EQ

class KVAC_MEQ:

    """
    Implementation of the Keyed-Verification Anonymous Credentials with Highly Efficient Partial Disclosure (KVAC-MEQ).
    This is described in section five of Keyed-Verification Anonymous Credentials.

    KVAC-MEQ combines:
    - DVSC: used to commit to an attribute set S and later open a subset D ⊆ S.
    - SP-MAC-EQ: used to authenticate the DVSC commitment as a message vector.

    The KVAC_MEQ Shceme works by combining the DVSC and SP_MAC_EQ Scheme. 
    The commitment of DVSC scheme has the following form: C = (C_1,C_2) = (f_S(v)G, G').
    Since the length of the commitment is bigger than 1, it can be used, as a message vector in SP-MAC-EQ Scheme.
    We can therefore autheticate the credentials createde with DVSC throught the SP-MAC-EQ Scheme. 

    When randomizing the credentials, we can utilize the same scalar μ for both schemes. 
    This way we get to both randomize the commitment, and keep the tags valid at the same time.

    Notation in paper and our correlating naming scheme:
    - sk_MEQ: secret MAC key for SP-MAC-EQ, sk = (x_1, x_2).
    - sk_DVSC: secret DVSC key, sk = v.
    - randomScalarR: blinding scalar r used in the MEQ issuer parameter.
    - iparMEQ: public MEQ issuer parameter, X = x_1G + x_2G' + rG''.
    - iparDVSC: public DVSC issuer parameters, consisting of proof and commitment basis.
    - commitment: DVSC commitment C = (C_1, C_2).
    - tagR, tagT: SP-MAC-EQ tag τ = (R, T) on the commitment.
    - proof: NIZK proof showing that the issued tag was created consistently.
    """

    def __init__(self, groupObject):

        """
        The constructor initializes the group context, samples the required genrators, 
        and initalizes the underlying DVSC and SP-MAC-EQ shceme with corresponding generators.
        This creates the public parameter setup of pp := (G_1, G_2, G_T, p, e, g1, g2, g', g'').

        Used by:
        - issuer/verfiier to setup the scheme KVAC-Scheme.

        Notation in paper and our correlating naming scheme:
        - self.g1 corresponds to G.
        - self.g2 corresponds to G_2.
        - self.gPrime corresponds to G'.
        - self.gPPrime corresponds to G''.

        Why er do this:
        KVAC-MEQ needs the group elements required for DVSC and SP-MAC-EQ.
        SP-MAC-EQ uses the g1 and g2 generator. 
        DVSC uses the two elements from G_1 denoted g1 and g'.
        The last g'' is used in creating the public public MEQ issuer parameter:

        iparMEQ = x_1G + x_2G' + rG''

        This allows for issuer to prove the tags from SP-MAC-EQ were generated consistenly with the hidden MAC key. 
        
        """
        
        self.group = groupObject
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.gPrime = self.group.random(G1)
        self.gPPrime = self.group.random(G1)

        self.SchemeDVSC = DVSC(self.group, self.g1, self.gPrime)
        self.SchemeMEQ = SP_MAC_EQ(self.group, self.g1, self.g2)


    def buildPIResponse(self, responseSequence, randomResponseSequence):

        """
        buildPIResponse() builds the response for the Fiat-Shamir tranformed proof

        Used by: 
        - The issuer, when doing issue cred. It's used through makeNIZK().

        Notation in paper and our correlating naming scheme:
        - challenge: corresponds to c.
        - tagRandom: corresponds to a^{-1}.
        - x1, x2: correspond to the SP-MAC-EQ secret key components.
        - randomScalar: corresponds to r in iparMEQ.
        - randomA, randomX1, randomX2, randomR: are the prover's random masks.
        
        """

        #get needed variables
        randomScalar, challenge, tagRandom, x1, x2 = responseSequence
        randomA, randomX1, randomX2, randomR = randomResponseSequence

        #compute the different components of PI proof
        sA = (randomA) + (challenge * tagRandom)
        sX1 = randomX1 + (challenge * x1)
        sX2 = randomX2 + (challenge * x2)
        sR = randomR + (challenge * randomScalar)

        return challenge, sA, sX1, sX2, sR
    

    def sigmaProtocol(self, randomScalar, x1, x2, r, commitment, tagR):

        """
        sigmaProtocol() compute the Sigma-protocol relation values in the NIZK proof.

        Used by:
        - Issuer to compute the random announcement.
        - User to recompute the accepting announcement sequence.

        Notation in paper and our correlating naming scheme:
        - commitment: C = (C_1, C_2).
        - tagR: corresponds to R from the SP-MAC-EQ tag.
        - x1, x2: are either real MAC key components or response values.
        - randomScalar: is either a^{-1}, a random mask, or a response value.
        - r: is either the blinding scalar from iparMEQ, a random mask, or a response value.
        
        Why we do this:
        The issuer has to prove that the tag was honestly generated using the secret MAC key that was used when commiting in iparMEQ. 
        It prevent a malicious issuer from returning invalid tags.
        """

        c1, c2 = commitment
        #compute X = x1 * G1 + x2 * G' + r * G''
        x = (x1 * self.g1) + (x2 * self.gPrime) + (r * self.gPPrime)
        #T is the same as tag T
        t1 = randomScalar * self.g2
        #compute x1 * C1 + x2 * C2
        t2 = (x1 * c1) + (x2 * c2) - (randomScalar * tagR)
        return x, t1, t2
    

    def makeNIZK(self, sk_MEQ, commitment, iparMEQ, tagR, tagT, disclosedAttributes, randomScalarR, randomScalarAInverse):

        """
        makeNIZK() creates the NIZK proof π for an issued credential.

        Used by:
        - issuer makes the proof doing the issue credential method.

        Notation in paper and our correlating naming scheme:
        - sk_MEQ: s_MEQ =  (x_1, x_2).
        - commitment: C = (C_1, C_2).
        - tagR, tagT: τ = (R, T).
        - randomScalarAInverse: corresponds to a^{-1}.
        - randomScalarR: corresponds to r in iparMEQ.
        - iparMEQ: iparMeq = x_1G + x_2G' + rG''.

        Why we do this:
        The user recieving the credential must ben able to verify the issuer creating the vlaid SP-MAC-EQ tag on the DVSC commitment.
        The issuer must not reveal the MAC secret key, so the NIZK proof is used to show taht teh tag and iparMEQ,
        are consistent with the same hidden value.        
        """

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
        announcementSequence = (disclosedAttributes, iparMEQ, *commitment, tagR, tagT, randomAnnouncement)
        #Hash the sequence to get the challenge
        challenge = self.SchemeDVSC.hashForChallenge(announcementSequence)

        #Make the two sequences that are needed to make the full Pi proof
        responseSequence = (randomScalarR, challenge, randomScalarAInverse, *sk_MEQ)
        randomResponseSequence = (randomProofAInverse, randomProofX1, randomProofX2, randomProofR)
        
        #Build the final PI response as the proof
        finalProof = self.buildPIResponse(responseSequence, randomResponseSequence)

        return finalProof

        
    def verifyNIZK(self, proofChallenge, proofSA, proofSX1, proofSX2, proofSR, commitment, disclosedAttributes, tagR, tagT, iparMEQ):


        """
        verifyNIZK() Verifies teh NIZK proof π computed doing the issuing of credentials. 

        Used by:
        - User when checking the validity of the credential.

        Notation in paper and our correlating naming scheme:
        - proofChallenge: corresponds to the Fiat-Shamir challenge c.
        - proofSA: corresponds to the response s_A for the witness a^{-1}.
        - proofSX1: corresponds to the response s_{x_1} for the MAC secret key component x_1.
        - proofSX2: corresponds to the response s_{x_2} for the MAC secret key component x_2.
        - proofSR: corresponds to the response s_r for the blinding scalar r used in iparMEQ.

        - commitment: corresponds to the DVSC commitment C = (C_1, C_2).
        - disclosedAttributes: corresponds to the attribute set S used to compute the commitment.
        - tagR and tagT: correspond to the SP-MAC-EQ tag τ = (R, T).
        - iparMEQ: corresponds to the public MEQ issuer parameter X = x_1G + x_2G' + rG''.

        - sigmaX, sigmaT1, sigmaT2: correspond to the recomputed Sigma-protocol values from the proof responses.
        - iparMEQ_UASPA, tagT_UASPA, zero_UASPA: correspond to the reconstructed accepting announcement values used to recompute the Fiat-Shamir challenge.
        - newChallenge: corresponds to the verifier's recomputed challenge c'.
        
        Why we do this:
        The user needs to verify that the issued SP-MAC-EQ tag is consisten with the commitment and iparMEQ,
        without getting information about the issuer's secret MAC key.
        """

        #Compute the first part for verifying the PI proof
        sigmaX, sigmaT1, sigmaT2 = self.sigmaProtocol(proofSA, proofSX1, proofSX2, proofSR, commitment, tagR)
    
        # unique accepting Sigma protocol announcement (UASPA)
        iparMEQ_UASPA = sigmaX - proofChallenge * iparMEQ
        tagT_UASPA = sigmaT1 - proofChallenge * tagT
        zero_UASPA = sigmaT2

        #make the sequence that is needed for the new challenge
        verifyChallengeAnnouncementSeq = (disclosedAttributes, iparMEQ, *commitment, tagR, tagT, (iparMEQ_UASPA, tagT_UASPA, zero_UASPA))

        #hash the sequence
        newChallenge = self.SchemeDVSC.hashForChallenge(verifyChallengeAnnouncementSeq)

        #check that the new challenge is the same as the challenge computed on the issuer side
        return proofChallenge == newChallenge


    def keyGen(self, attributeListSize):
        
        """
        keygen() generates the issuers secret key and the public issuser parameters.

        Used by:
        - Issuer/verifier when setting up the scheme.

        Notation in paper and our correlating naming scheme:
        - sk_MEQ: corresponds to sk_MEQ = (x_1, x_2), the SP-MAC-EQ secret key.
        - sk_DVSC: correspond to sk_DVSC = v, the DVSC secret key.
        - randomScalarR: correspond to the blinding scalar used in iparMEQ.
        - iparMEQ: corresponds to iparMEQ = x_1G + x_2G' + rG''.
        - iparDVSC: corresponds to iparDVSC = (challenge, response, commitmentBasis).

        Why we do this:
        KVAC-MEQ needs both the MAC key for authentication, and the DVSC key and commitment basis,
        when computing opening of subsets.
        The iparMEQ lets user prove the consistensy of the issued MAC tags without revaeling MAC secret.
        """

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
    

    def issueCred(self, disclosedAttributes, isk, commitmentBasis, iparMEQ):

        """
        issueCred() creates a user's credentials on the attributes set. 

        Used by:
        - Issuer to create the credential.

        Notation in paper and our correlating naming scheme:
        - disclosedAttributes: corresponds to the committed attribute set S.
        - commitment: corresponds to C = (f_S(v)G, G').
        - tagR, tagT: correspond to the SP-MAC-EQ tag τ = (R, T).
        - proof: is the NIZK proof that the tag was issued consistently.     

        Why we do this:
        The issuer first computes the deterministic DVSC commitment to the attribute set.
        The commitment is then authenticated using the SP-MAC-EQ scheme.
        The MAC tag crated is then used as credentials.
        Here the NIZK is also computed, so user can verify the consistensy of the tag creation.
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
        while randomScalarA == self.group.init(ZR):
            randomScalarA = self.group.random(ZR)
        randomScalarAInverse = randomScalarA ** -1

        #compute the tag from the MEQ scheme
        tagR, tagT = self.SchemeMEQ.createMac(sk_MEQ, list(commitment), randomScalarA)
      
        # Proof time :)
        proof = self.makeNIZK(sk_MEQ, commitment, iparMEQ, tagR, tagT, disclosedAttributes, randomScalarR, randomScalarAInverse)

        return tagR, tagT, proof, list(commitment), commitment
    
    
    def obtainCred(self, disclosedAttributes, iparDVSC, iparMEQ, proof, tagR, tagT, checkIssuerParameter=False):

        """
        obtainCred() verifies the credentail which gets issued by the issuer.

        Used by.
        - User uses the method to verify the valdity of the tags.

        Notation in paper and our correlating naming scheme:
        - disclosedAttributes: corresponds to the user's full committed attribute set S.
        - iparDVSC: contains the DVSC issuer parameters.
        - iparMEQ: is the public MEQ issuer parameter.
        - proof: is the NIZK proof returned by the issuer.
        - tagR, tagT: are the SP-MAC-EQ tag components.

        Why we do this:
        Before accepting a given credential, the user must check the issuer's tag
        is consisten with the commitment and ipar.
        This is done by recomputing the commitment and verifying the NIZK proof.
        """

        #get needed variables
        proofChallenge, proofSA, proofSX1, proofSX2, proofSR = proof
        challenge, response, commitmentBasis = iparDVSC

        if checkIssuerParameter:
            if not self.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis):
                return None

        #make commitment
        commitment = self.SchemeDVSC.commit(commitmentBasis, disclosedAttributes)

        #check that iparDVSC is valid
        if commitment is None:
            return None

        # Proof time :)
        check = self.verifyNIZK(proofChallenge, proofSA, proofSX1, proofSX2, proofSR, commitment, disclosedAttributes, tagR, tagT, iparMEQ)

        if check == False:
            return None
        
        return (tagR, tagT), commitment
    

    def showCred(self, tagR, tagT, commitment, disclosedAttributes, requiredAttributesSubset, encodedMessages, iparDVSC):
        
        """
        showCred() is used to create a new randomized presentation.

        Used by:
        - User uses the showCred() when presenting their credentials to a verifier.

        Notation in paper and our correlating naming scheme:
        - encodedMessages: corresponds to the original commitment C.
        - requiredAttributesSubset: corresponds to the disclosed subset D.
        - randomScalarMu: corresponds to μ.
        - randomizedTag: is the adapted SP-MAC-EQ tag on μC.
        - randomizedCommitment: is the randomized DVSC commitment C'.
        - witness: is the subset opening W = μ f_{S\D}(v)G.

        Why we do this:
        The method is used to present the users credentials.
        It uses the randomization and changeRepresentation algorithms from SP-MAC-EQ and DVSC to create an unlinkable presentaion.
        Both sub shcemes uses the same randomScalarMu as to ensure that verfication on randomized commitment works via randomized tag,
        and that the subset witness verifies correctly agains teh randomized commitment.
        """

        #get random scalar
        randomScalarMu = self.group.random(ZR)
        while randomScalarMu == self.group.init(ZR):
            randomScalarMu = self.group.random(ZR)

        _,_, commitmentBasis = iparDVSC

        #compute the randomized tag
        randomizedTag = self.SchemeMEQ.changeRepresentation(encodedMessages, tagR, tagT, randomScalarMu)

        #compute randomized commitment
        randomizedCommitment = self.SchemeDVSC.randomize(*commitment, randomScalarMu)

        #compute witness
        witness = self.SchemeDVSC.openSubset(commitmentBasis, disclosedAttributes, requiredAttributesSubset, randomScalarMu)

        return randomizedTag, randomizedCommitment, witness


    def verify(self, randomizedTag, randomizedCommitment, witness, requiredAttributesSubset, isk):

        """
        verify() verifies the randomized credential presentation

        Used by:
        - Verifier when checking a users credential.

        Notation in paper and our correlating naming scheme:       
        - randomizedTag: contains the changed message vector and adapted MAC tag.
        - randomizedCommitment: corresponds to C' = (C_1', C_2').
        - witness: corresponds to W = μ f_{S\D}(v)G.
        - requiredAttributesSubset: corresponds to D.

        Why we do this:
        The verification checks to things:
        First the SP-MAC-EQ verification, which ensures the randomized tags validity agains the randomized commitment.
        Then the DVSC subset verification, ensuring the disclosde subset is contained in the commited set S.
        If both check are valid, a users credentials will be verified.
        """

        sk_MEQ, sk_DVSC, _ = isk
        changedMessages, tagR, tagT = randomizedTag

        #use functions from other two scheme to verify the subset and commtiment
        verifyMEQ = self.SchemeMEQ.verify(sk_MEQ, changedMessages, tagR, tagT)
        verifySubset = self.SchemeDVSC.verifySubset(
            sk_DVSC, randomizedCommitment[0], witness, requiredAttributesSubset
        )

        return verifyMEQ and verifySubset



    







    








        




