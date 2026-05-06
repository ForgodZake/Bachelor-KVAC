from charm.toolbox.pairinggroup import PairingGroup, ZR
from KVAC_MEQ_Scheme import KVAC_MEQ


def test_KVAC_MEQ_verifies_correctly():

    group = PairingGroup('SS512')
    scheme = KVAC_MEQ(group)

    attributeList = ["age", "nationality", "occupation"]
    subset = ["age"]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in subset]

    

    isk, ipar, gPrime = scheme.keyGen(len(attributeList))
    ipar_MEQ, ipar_DVSC = ipar
    _, _, commitmentBasis = ipar_DVSC

    #make secret key
    usk = group.random(ZR)
    while usk == group.init(ZR):
        usk = group.random(ZR)
    
    #make public key
    upk = usk * gPrime

    tagR, tagT, response, encodedMessages, commitment = scheme.issueCred(disclosedAttributes, isk, commitmentBasis, ipar_MEQ, upk)

    assert commitment is not None

    checkedCommmitment = scheme.obtainCred(disclosedAttributes, ipar_DVSC, ipar_MEQ, response, tagR, tagT, upk)

    assert checkedCommmitment is not None

    randomizedTag, randomizedCommitment, witness, proof = scheme.showCred(
        tagR, tagT, disclosedAttributes, disclosedAttributeSubset, encodedMessages, ipar, upk, usk
    )

    assert scheme.verify(randomizedTag, randomizedCommitment, witness, disclosedAttributeSubset, isk, proof, ipar) == True