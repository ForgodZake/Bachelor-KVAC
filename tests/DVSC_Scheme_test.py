from charm.toolbox.pairinggroup import G1, ZR, pair, PairingGroup
from DVSC_Scheme import DVSC

def test_keyGen_and_Commit():

    group = PairingGroup('SS512')
    scheme = DVSC(group)

    attributeList = ["age", "nationality", "occupation"]

    secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))

    commitment, randomScalarG1 = scheme.commit(challenge, response, commitmentBasis, attributeList)

    print("Commitment: ", commitment)
    
    randomScalarMu = group.random(ZR)

    newCommitment, _ = scheme.randomize(commitment, randomScalarG1, randomScalarMu)

    print("newCommitment: ", newCommitment)

    attributeSubsetRaw = ["age"]
    witness = scheme.openSubset(commitmentBasis, attributeList, attributeSubsetRaw, randomScalarMu)

    print("witness: ", witness)

    assert scheme.verifySubset(secretKey, newCommitment, witness, attributeSubsetRaw) == True
