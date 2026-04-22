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

    isk, ipar = scheme.keyGen()

    tag, basis, pi = scheme.issueCred(disclosedAttributes, isk, ipar)

    tag, basis = scheme.obtainCred(tag, basis, pi, disclosedAttributes, ipar)

    assert tag, basis is not None

    randomizedTag, witness = scheme.showCred(tag, basis, disclosedAttributes, disclosedAttributeSubset)

    assert scheme.verify(randomizedTag, witness, disclosedAttributeSubset, isk) == True

