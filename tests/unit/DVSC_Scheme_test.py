from charm.toolbox.pairinggroup import ZR, G1, PairingGroup
from DVSC_Scheme import DVSC

def test_two_differently_randomized_commitments_both_verifies():

    group = PairingGroup('SS512')
    g1 = group.random(G1)
    gPrime = group.random(G1)
    scheme = DVSC(group, g1, gPrime)
    

    attributeList = ["age", "nationality", "occupation"]

    secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))

    commitment = scheme.commit(challenge, response, commitmentBasis, attributeList)
    
    randomScalarMu = group.random(ZR)
    differentRandomScalarMu = group.random(ZR)

    assert randomScalarMu != differentRandomScalarMu

    newCommitment, _ = scheme.randomize(*commitment, randomScalarMu)
    differentNewCommitment, _ = scheme.randomize(*commitment, differentRandomScalarMu)

    requiredAttributeSubsetRaw = ["age"]
    witness = scheme.openSubset(commitmentBasis, attributeList, requiredAttributeSubsetRaw, randomScalarMu)
    differentWitness = scheme.openSubset(commitmentBasis, attributeList, requiredAttributeSubsetRaw, differentRandomScalarMu)

    assert scheme.verifySubset(secretKey, newCommitment, witness, requiredAttributeSubsetRaw) == True
    assert scheme.verifySubset(secretKey, differentNewCommitment, differentWitness, requiredAttributeSubsetRaw) == True


