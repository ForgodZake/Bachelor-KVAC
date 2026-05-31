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
        (2**5, 2**4),
        (2**6, 2**5),
        (2**7, 2**6),
        (2**8, 2**7),
        (2**9, 2**8),
        (2**10, 2**9),
        (2**11, 2**10),
        (2**12, 2**11),
    ]

    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "FromPaper")



def test_DVSC_increase_only_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC increase only subset benchmarks:")

    benchmarkSizes = [
        (2**12, 2**2),
        (2**12, 2**3),
        (2**12, 2**4),
        (2**12, 2**5),
        (2**12, 2**6),
        (2**12, 2**7),
        (2**12, 2**8),
        (2**12, 2**9),
        (2**12, 2**10),
        (2**12, 2**11),
        (2**12, 2**12),
        
    ]

    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlySubset")


def test_DVSC_increase_only_attributeList_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("DVSC increase only attributeList benchmarks:")

    benchmarkSizes = [
        (2**2, 1),
        (2**3, 1),
        (2**4, 1),
        (2**5, 1),
        (2**6, 1),
        (2**7, 1),
        (2**8, 1),
        (2**9, 1),
        (2**10, 1),
        (2**11, 1),
        (2**12, 1),
        
    ]

    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "DVSC", "increaseOnlyAttributeList")

def runBenchmark(attributeCount, subsetCount, group):

    repetitions = 5

    totalTimes = [0, 0, 0, 0, 0]

    for _ in range(repetitions):
        g1 = group.random(G1)
        gPrime = group.random(G1)
        scheme = DVSC(group, g1, gPrime)

        attributeList = setup.buildAttributeList(attributeCount)
        attributeSubsetList = attributeList[:subsetCount]
        disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
        disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in attributeSubsetList]

        start = time.perf_counter()
        secretKey, challenge, response, commitmentBasis = scheme.keyGen(len(attributeList))
        end = time.perf_counter()
        totalTimes[0] += (end-start)

        start = time.perf_counter()
        _ = scheme.verifyIssuerParameter(challenge, response, commitmentBasis)
        commitment = scheme.commit(commitmentBasis, disclosedAttributes)
        end = time.perf_counter()
        totalTimes[1] += (end-start)
        
        randomScalarMu = group.random(ZR)

        start = time.perf_counter()
        newCommitment, _ = scheme.randomize(*commitment, randomScalarMu)
        end = time.perf_counter()
        totalTimes[2] += (end-start)

        start = time.perf_counter()
        witness = scheme.openSubset(commitmentBasis, disclosedAttributes, disclosedAttributeSubset, randomScalarMu)
        end = time.perf_counter()
        totalTimes[3] += (end-start)

        start = time.perf_counter()
        scheme.verifySubset(secretKey, newCommitment, witness, disclosedAttributeSubset)
        end = time.perf_counter()
        totalTimes[4] += (end-start)
    
    averageTimes = [
        t / repetitions
        for t in totalTimes
    ]

    print("")
    print("AttributeSetSize:", len(attributeList))
    print("AttributeSubsetSize:", len(attributeSubsetList))
    print("")
    print("Averaged over", repetitions, "runs")
    print("")
    print("keyGen time (ms):", averageTimes[0] * 1000)
    print("commit time (ms):", averageTimes[1] * 1000)
    print("randomize time (ms):", averageTimes[2] * 1000)
    print("openSubset (ms):", averageTimes[3] * 1000)
    print("verifySubset time (ms):", averageTimes[4] * 1000)

    return averageTimes