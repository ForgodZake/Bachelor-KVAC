from charm.toolbox.ecgroup import ECGroup, ZR
from charm.toolbox.eccurve import secp256k1
from KVAC_GGM_Scheme import KVAC_GGM


def test_KVAC_GGM_verifies_correctly():
    group = ECGroup(secp256k1)
    scheme = KVAC_GGM(group)

    attributeList = ["age", "nationality", "occupation"]
    subset = ["age"]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in subset]

    isk, ipar, gPrime = scheme.keyGen()
        #make secret key

    usk = group.random(ZR)
    while usk == group.init(ZR):
        usk = group.random(ZR)

    #make public key
    upk = gPrime ** usk

    tag, basis, pi = scheme.issueCred(disclosedAttributes, isk, ipar, upk)

    tag, basis, commitment = scheme.obtainCred(tag, basis, pi, disclosedAttributes, ipar, upk)

    assert tag, basis is not None

    randomizedTag, witness, proof, randomizedUpk, randomizedGPrime, randomizedCommitment = scheme.showCred(tag, basis, disclosedAttributes, disclosedAttributeSubset, usk, upk, ipar, commitment)

    assert scheme.verify(randomizedTag, witness, disclosedAttributeSubset, isk, randomizedCommitment, ipar, randomizedUpk, randomizedGPrime, proof) == True

