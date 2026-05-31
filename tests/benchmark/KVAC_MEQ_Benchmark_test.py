from charm.toolbox.pairinggroup import PairingGroup, ZR
from KVAC_MEQ_Scheme import KVAC_MEQ
import generalBenchMarkSetup as setup
import pytest
import time


@pytest.fixture
def group():
    return PairingGroup('SS512')


@pytest.fixture
def algorithmNames():
    return ["keyGen_", "issueCred_", "obtainCred_", "showCred_", "verify_"]


def test_KVAC_MEQ_from_paper_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_MEQ from paper benchmarks:")

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
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_MEQ", "FromPaper")



def test_KVAC_MEQ_increase_only_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_MEQ increase only subset benchmarks:")

    
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
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_MEQ", "increaseOnlySubset")


def test_KVAC_MEQ_increase_only_attributeList_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_MEQ increase only attributeList benchmarks:")
    
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
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_MEQ", "increaseOnlyAttributeList")


def runBenchmark(attributeCount, subsetCount, group):

    repetitions = 5

    totalTimes = [0, 0, 0, 0, 0]

    credentialSizeKiB = 0
    presentationSizeKiB = 0

    for _ in range(repetitions):
        scheme = KVAC_MEQ(group)

        attributeList = setup.buildAttributeList(attributeCount)
        attributeSubsetList = attributeList[:subsetCount]
        disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
        disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in attributeSubsetList]

        start = time.perf_counter()
        isk, ipar = scheme.keyGen(len(attributeList))
        end = time.perf_counter()
        totalTimes[0] += (end-start)

        ipar_MEQ, ipar_DVSC = ipar
        challenge, response, commitmentBasis = ipar_DVSC

        assert scheme.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis)
        
        start = time.perf_counter()
        tagR, tagT, response, encodedMessages, _ = scheme.issueCred(
            disclosedAttributes, isk, commitmentBasis, ipar_MEQ
        )
        end = time.perf_counter()
        totalTimes[1] += (end-start)

        start = time.perf_counter()
        tagR, tagT = scheme.obtainCred(
            disclosedAttributes, ipar_DVSC, ipar_MEQ, response, tagR, tagT, False
        )
        end = time.perf_counter()
        totalTimes[2] += (end-start)

        start = time.perf_counter()
        randomizedTag, randomizedCommitment, witness = scheme.showCred(
            tagR, tagT, disclosedAttributes, disclosedAttributeSubset, encodedMessages, ipar_DVSC
        )
        end = time.perf_counter()
        totalTimes[3] += (end-start)

        start = time.perf_counter()
        _ = scheme.verify(
            randomizedTag, randomizedCommitment, witness, disclosedAttributeSubset, isk
        )
        end = time.perf_counter()
        totalTimes[4] += (end-start)

        credentialSizeKiB = (setup.sizeBytes(tagR, group) + setup.sizeBytes(tagT, group)) / 1024
        presentationSizeKiB = (
            setup.sizeBytes(randomizedTag, group)
            + setup.sizeBytes(randomizedCommitment, group)
            + setup.sizeBytes(witness, group)
        ) / 1024

    averageTimes = [
        t / repetitions
        for t in totalTimes
    ]

    print("")
    print("AttributeSetSize:", len(attributeList))
    print("AttributeSubsetSize:", len(attributeSubsetList))
    print("credentialSize (KiB):", credentialSizeKiB)
    print("presentationSize (KiB):", presentationSizeKiB)
    print("")
    print("Averaged over", repetitions, "runs")
    print("")
    print("keyGen time (ms):", averageTimes[0] * 1000)
    print("issueCred time (ms):", averageTimes[1] * 1000)
    print("obtainCred time (ms):", averageTimes[2] * 1000)
    print("showCred time (ms):", averageTimes[3] * 1000)
    print("verifyCred time (ms):", averageTimes[4] * 1000)

    return averageTimes