from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
from SP_MAC_EQ_Scheme import SP_MAC_EQ
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
    randomScalar = group.random(ZR)
    scheme = SP_MAC_EQ(group, g1, gPrime)
    times = []


    attributeList = buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]

    start = time.perf_counter()
    secretKey = scheme.keyGen(len(attributeList))
    end = time.perf_counter()
    times.append(end - start)

    encodedMessages = [group.hash(message, G1) for message in attributeList]

    start = time.perf_counter()
    tagR, tagT = scheme.createMac(secretKey, encodedMessages, randomScalar)
    end = time.perf_counter()
    times.append(end - start)
    
    randomScalarMu = group.random(ZR)

    start = time.perf_counter()
    changedMessages, newTagR, newTagT = scheme.changeRepresentation(encodedMessages, tagR, tagT, randomScalarMu)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verify(secretKey, changedMessages, newTagR, newTagT)
    end = time.perf_counter()
    times.append(end - start)

    print("")
    print("AttributeSetSize:", len(attributeList))
    print("AttributeSubsetSize:", len(attributeSubsetList))
    print("")
    print("keyGen time (ms):", times[0] * 1000)
    print("createMac time (ms):", times[1] * 1000)
    print("changeRepresentation time (ms):", times[2] * 1000)
    print("verify (ms):", times[3] * 1000)


def test_SP_MAC_EQ_benchmarks(group):

    print("")
    print("")
    print("SP_MAC_EQ Bencmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    for attributeCount, subsetCount in benchmarkSizes:
        runBenchmark(attributeCount, subsetCount, group)