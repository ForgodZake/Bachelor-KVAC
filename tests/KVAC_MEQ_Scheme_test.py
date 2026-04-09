from charm.toolbox.pairinggroup import ZR, PairingGroup
import KVAC_MEQ_Scheme as KVAC_MEQ

def hopeItWorks():
    group = PairingGroup('SS512')
    scheme = KVAC_MEQ(group)

    attributeList = ["age", "nationality", "occupation"]

    subset = ["age"]

    isk, ipar = scheme.keyGen(len(attributeList))

    _, ipar_DVSC = ipar

    _, _, commitmentBasis = ipar_DVSC

    tagR, tagT, _, encodedMessages = scheme.issueCred(attributeList, isk, ipar)

    commitment = scheme.obtainCred(attributeList, ipar_DVSC)

    assert commitment != None

    randomizedTag, randomizedCommitment, witness = scheme.showCred(tagR, tagT, attributeList, subset, encodedMessages, commitmentBasis, commitment)

    verify = scheme.verify(randomizedTag, randomizedCommitment, witness, subset, isk)

    assert verify == True