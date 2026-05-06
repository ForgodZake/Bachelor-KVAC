from charm.toolbox.pairinggroup import ZR, G1, PairingGroup
from DVSC_Scheme import DVSC


def test_two_differently_randomized_commitments_both_verifies():

    group = PairingGroup('SS512')
    g1 = group.random(G1)
    gPrime = group.random(G1)
    scheme = DVSC(group, g1, gPrime)

    upk = group.random(ZR)
    
    attributeList = ["age", "nationality", "occupation"]
    requiredAttributeSubsetRaw = ["age"]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in requiredAttributeSubsetRaw]

    secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))

    assert scheme.verifyIssuerParameter(challenge, response, commitmentBasis)

    commitment = scheme.commit(commitmentBasis, disclosedAttributes)
    
    randomScalarMu = group.random(ZR)
    differentRandomScalarMu = group.random(ZR)

    assert randomScalarMu != differentRandomScalarMu

    newCommitment, _, _ ,_  = scheme.randomize(*commitment, randomScalarMu, upk, gPrime)
    differentNewCommitment, _, _ ,_ = scheme.randomize(*commitment, differentRandomScalarMu, upk, gPrime)

    witness = scheme.openSubset(commitmentBasis, disclosedAttributes, disclosedAttributeSubset, randomScalarMu)
    differentWitness = scheme.openSubset(commitmentBasis, disclosedAttributes, disclosedAttributeSubset, differentRandomScalarMu)

    assert scheme.verifySubset(secretKey, newCommitment, witness, disclosedAttributeSubset) == True
    assert scheme.verifySubset(secretKey, differentNewCommitment, differentWitness, disclosedAttributeSubset) == True


