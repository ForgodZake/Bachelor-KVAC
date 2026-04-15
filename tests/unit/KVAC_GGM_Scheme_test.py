from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import secp256k1
from KVAC_GGM_Scheme import KVAC_GGM

def test_KVAC_GGM_verifies_correctly():
    group = ECGroup(secp256k1)
    scheme = KVAC_GGM(group)

    attributeList = ["age", "nationality", "occupation"]
    subset = ["age"]

    isk, ipar = scheme.keyGen()

    tag, basis, pi = scheme.issueCred(attributeList, isk, ipar)

    tag, basis = scheme.obtainCred(tag, basis, pi, attributeList, ipar)

    assert tag, basis is not None

    randomizedTag, witness = scheme.showCred(tag, basis, attributeList, subset)

    assert scheme.verify(randomizedTag, witness, subset, isk) == True

