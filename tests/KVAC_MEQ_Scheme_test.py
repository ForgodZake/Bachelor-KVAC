from charm.toolbox.pairinggroup import ZR, PairingGroup
from KVAC_MEQ_Scheme import KVAC_MEQ

def test_hopeItWorks():

    group = PairingGroup('SS512')
    scheme = KVAC_MEQ(group)

    attributeList = ["age", "nationality", "occupation"]
    subset = ["age"]

    isk, ipar = scheme.keyGen(len(attributeList))
    _, ipar_DVSC = ipar
    _, _, commitmentBasis = ipar_DVSC

    tagR, tagT, _, encodedMessages, commitment = scheme.issueCred(attributeList, isk, ipar_DVSC)

    assert commitment is not None

    randomizedTag, randomizedCommitment, witness = scheme.showCred(
        tagR, tagT, attributeList, subset, encodedMessages, commitmentBasis, commitment
    )

    assert scheme.verify(randomizedTag, randomizedCommitment, witness, subset, isk) == True