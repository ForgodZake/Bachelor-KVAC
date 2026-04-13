from charm.toolbox.pairinggroup import ZR, PairingGroup
from KVAC_GGM_Scheme import KVAC_GGM

def test_kvac():
    group = PairingGroup('SS512')
    scheme = KVAC_GGM(group)

    attributeList = ["age", "nationality", "occupation"]
    subset = ["age"]

    isk, ipar = scheme.keyGen()

    tag, basis, pi = scheme.issueCred(attributeList, isk, ipar)

    tag, basis = scheme.obtainCred(tag, basis, pi, attributeList, ipar)

    assert tag, basis is not None

