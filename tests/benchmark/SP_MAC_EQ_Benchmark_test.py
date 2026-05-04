from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
from SP_MAC_EQ_Scheme import SP_MAC_EQ
import generalBenchMarkSetup as setup
import pytest
import time

@pytest.fixture
def group():
    return PairingGroup('SS512')

@pytest.fixture
def algorithmNames():
    return ["keyGen_", "createMac_", "changeRepresentation_", "verify_"]


def test_SP_MAC_EQ_from_paper_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("SP_MAC_EQ from paper benchmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "FromPaper")


def test_SP_MAC_EQ_increase_attributes_and_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("SP_MAC_EQ increase attributes and subset benchmarks:")

    benchmarkSizes = []

    for i in range(2, 2**8):
        if i % 2 != 0:
            benchmarkSizes.append((i, int((i+1)/2)))
        else:
            benchmarkSizes.append((i, int(i/2)))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseAttributesAndSubset")


def test_SP_MAC_EQ_increase_only_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("SP_MAC_EQ increase only subset benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**8):
        benchmarkSizes.append((2**8, i))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlySubset")


def test_SP_MAC_EQ_increase_only_attributeList_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("SP_MAC_EQ increase only attributeList benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**8):
        benchmarkSizes.append((i, 1))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlyAttributeList")


def runBenchmark(attributeCount, subsetCount, group):

    g1 = group.random(G1)
    gPrime = group.random(G1)
    randomScalar = group.random(ZR)
    scheme = SP_MAC_EQ(group, g1, gPrime)
    times = []


    attributeList = setup.buildAttributeList(attributeCount)
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

    return times