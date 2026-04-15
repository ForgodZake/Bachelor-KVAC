from charm.toolbox.pairinggroup import ZR, G1, PairingGroup
from DVSC_Scheme import DVSC
import time
import pytest


@pytest.fixture
def group():
    return PairingGroup('SS512')


def sizeBytes(value, group):
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, (list, tuple)):
        total = 0
        for item in value:
            total += sizeBytes(item, group)
        return total
    return len(group.serialize(value))


def buildAttributeList(attributeCount):
    attributeList = []
    baseAttribute = "attribute"

    for i in range(attributeCount):
        newAttribute = baseAttribute + str(i)
        attributeList.append(newAttribute)

    return attributeList


def runBenchmark(attributeCount, subsetCount, group):

    g1 = group.random(G1)
    gPrime = group.random(G1)
    scheme = DVSC(group, g1, gPrime)
    times = []
    

    attributeList = buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]

    start = time.perf_counter()
    secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verifyIssuerParameter(challenge, response, commitmentBasis)
    commitment = scheme.commit(commitmentBasis, attributeList)
    end = time.perf_counter()
    times.append(end - start)
    
    randomScalarMu = group.random(ZR)

    start = time.perf_counter()
    newCommitment, _ = scheme.randomize(*commitment, randomScalarMu)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    witness = scheme.openSubset(commitmentBasis, attributeList, attributeSubsetList, randomScalarMu)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    scheme.verifySubset(secretKey, newCommitment, witness, attributeSubsetList)
    end = time.perf_counter()
    times.append(end - start)

    print("")
    print("AttributeSetSize:", len(attributeList))
    print("AttributeSubsetSize:", len(attributeSubsetList))
    print("")
    print("keyGen time (ms):", times[0] * 1000)
    print("commit time (ms):", times[1] * 1000)
    print("randomize time (ms):", times[2] * 1000)
    print("openSubset (ms):", times[3] * 1000)
    print("verifySubset time (ms):", times[4] * 1000)


def test_DVSC_benchmarks(group):

    print("")
    print("")
    print("DVSC Bencmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    for attributeCount, subsetCount in benchmarkSizes:
        runBenchmark(attributeCount, subsetCount, group)