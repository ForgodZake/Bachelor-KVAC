from charm.toolbox.pairinggroup import ZR, G1, PairingGroup
from DVSC_Scheme import DVSC
import generalBenchMarkSetup as setup
import time
import pytest

@pytest.fixture
def group():
    return PairingGroup('SS512')

@pytest.fixture
def algorithmNames():
    return ["keyGen_", "commit_", "randomize_", "openSubset_", "verify_"]


def test_DVSC_from_paper_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC from paper benchmarks:")

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


def test_DVSC_increase_attributes_and_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC increase attributes and subset benchmarks:")

    benchmarkSizes = []

    for i in range(2, 2**12):
        if i % 2 != 0:
            benchmarkSizes.append((i, int((i+1)/2)))
        else:
            benchmarkSizes.append((i, int(i/2)))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseAttributesAndSubset")


def test_DVSC_increase_only_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC increase only subset benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**12):
        benchmarkSizes.append((2**12, i))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlySubset")


def test_DVSC_increase_only_attributeList_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC increase only attributeList benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**12):
        benchmarkSizes.append((i, 1))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlyAttributeList")

def runBenchmark(attributeCount, subsetCount, group):

    g1 = group.random(G1)
    gPrime = group.random(G1)
    scheme = DVSC(group, g1, gPrime)
    upk = group.random(ZR)
    times = []
    

    attributeList = setup.buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in attributeSubsetList]

    start = time.perf_counter()
    secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verifyIssuerParameter(challenge, response, commitmentBasis)
    commitment = scheme.commit(commitmentBasis, disclosedAttributes)
    end = time.perf_counter()
    times.append(end - start)
    
    randomScalarMu = group.random(ZR)

    start = time.perf_counter()
    newCommitment, _, _, _ = scheme.randomize(*commitment, randomScalarMu, upk, gPrime)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    witness = scheme.openSubset(commitmentBasis, disclosedAttributes, disclosedAttributeSubset, randomScalarMu)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    scheme.verifySubset(secretKey, newCommitment, witness, disclosedAttributeSubset)
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

    return times