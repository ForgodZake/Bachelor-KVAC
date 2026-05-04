from charm.toolbox.ecgroup import ECGroup, ZR
from charm.toolbox.eccurve import secp256k1
from KVAC_GGM_Scheme import KVAC_GGM
import generalBenchMarkSetup as setup
import pytest
import time



@pytest.fixture
def group():
    return ECGroup(secp256k1)

@pytest.fixture
def algorithmNames():
    return ["keyGen_", "issueCred_", "obtainCred_", "showCred_", "verify_"]


def test_KVAC_GGM_from_paper_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_GGM from paper benchmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_GGM", "FromPaper")


def test_DVSC_increase_attributes_and_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_GGM increase attributes and subset benchmarks:")

    benchmarkSizes = []

    for i in range(2, 2**8):
        if i % 2 != 0:
            benchmarkSizes.append((i, int((i+1)/2)))
        else:
            benchmarkSizes.append((i, int(i/2)))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_GGM", "increaseAttributesAndSubset")


def test_DVSC_increase_only_subset_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_GGM increase only subset benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**8):
        benchmarkSizes.append((2**8, i))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_GGM", "increaseOnlySubset")


def test_DVSC_increase_only_attributeList_benchmarks(group, algorithmNames):

    print("")
    print("")
    print("KVAC_GGM increase only attributeList benchmarks:")

    benchmarkSizes = []

    for i in range(1, 2**8):
        benchmarkSizes.append((i, 1))


    algorithmNames, measurements, attributeSubsetCount = setup.getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames)

    for name in algorithmNames:
        setup.plotTime(measurements[name], attributeSubsetCount, name, "KVAC_GGM", "increaseOnlyAttributeList")

def runBenchmark(attributeCount, subsetCount, group):
    scheme = KVAC_GGM(group)
    times = []

    attributeList = setup.buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in attributeSubsetList]

    start = time.perf_counter()
    isk, ipar = scheme.keyGen()
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tag, basis, pi = scheme.issueCred(disclosedAttributes, isk, ipar)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tag, basis = scheme.obtainCred(tag, basis, pi, disclosedAttributes, ipar)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    randomizedTag, witness = scheme.showCred(tag, basis, disclosedAttributes, disclosedAttributeSubset)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verify(randomizedTag, witness, disclosedAttributeSubset, isk)
    end = time.perf_counter()
    times.append(end - start)

    credentialSizeKiB = (setup.sizeBytes(tag, group) + setup.sizeBytes(basis, group)) / 1024
    presentationSizeKiB = (setup.sizeBytes(randomizedTag, group) + setup.sizeBytes(witness, group)) / 1024

    print("")
    print("AttributeSetSize:", len(attributeList))
    print("AttributeSubsetSize:", len(attributeSubsetList))
    print("credentialSize (KiB):", credentialSizeKiB)
    print("presentationSize (KiB):", presentationSizeKiB)
    print("")
    print("keyGen time (ms):", times[0] * 1000)
    print("issueCred time (ms):", times[1] * 1000)
    print("obtainCred time (ms):", times[2] * 1000)
    print("showCred time (ms):", times[3] * 1000)
    print("verifyCred time (ms):", times[4] * 1000)

    return times