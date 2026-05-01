from charm.toolbox.pairinggroup import PairingGroup, ZR
from KVAC_MEQ_Scheme import KVAC_MEQ
import matplotlib.pyplot as plt
import pytest
import time


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
    scheme = KVAC_MEQ(group)
    times = []

    attributeList = buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]
    disclosedAttributes = [group.hash(attribute, ZR) for attribute in attributeList]
    disclosedAttributeSubset = [group.hash(attribute, ZR) for attribute in attributeSubsetList]

    start = time.perf_counter()
    isk, ipar = scheme.keyGen(len(attributeList))
    end = time.perf_counter()
    times.append(end - start)

    ipar_MEQ, ipar_DVSC = ipar
    challenge, response, commitmentBasis = ipar_DVSC

    assert scheme.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis)
    
    start = time.perf_counter()
    tagR, tagT, response, encodedMessages, _ = scheme.issueCred(
        disclosedAttributes, isk, commitmentBasis, ipar_MEQ
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tagR, tagT = scheme.obtainCred(
        disclosedAttributes, ipar_DVSC, ipar_MEQ, response, tagR, tagT, False
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    randomizedTag, randomizedCommitment, witness = scheme.showCred(
        tagR, tagT, disclosedAttributes, disclosedAttributeSubset, encodedMessages, ipar_DVSC
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verify(
        randomizedTag, randomizedCommitment, witness, disclosedAttributeSubset, isk
    )
    end = time.perf_counter()
    times.append(end - start)

    credentialSizeKiB = (sizeBytes(tagR, group) + sizeBytes(tagT, group)) / 1024
    presentationSizeKiB = (
        sizeBytes(randomizedTag, group)
        + sizeBytes(randomizedCommitment, group)
        + sizeBytes(witness, group)
    ) / 1024

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


def test_KVAC_MEQ_benchmarks(group):

    print("")
    print("")
    print("KVAC_MEQ Benchmarks:")

    benchmarkSizes = []

    #test 1
    for i in range(2, 2**12):
        if i % 2 != 0:
            benchmarkSizes.append((i, int((i+1)/2)))
        else:
            benchmarkSizes.append((i, int(i/2)))
    """
    #test 2
    for i in range(1, 2**12):
        benchmarkSizes.append((2**12, i))

    # paper test marks    
    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]"""

    algorithmNames = ["keyGen", "issueCred", "obtainCred", "showCred", "verify"]
    measurements = {name: [] for name in algorithmNames}
    attributeSubsetCount = []

    for attributeCount, subsetCount in benchmarkSizes:
        times = runBenchmark(attributeCount, subsetCount, group)
        attributeSubsetCount.append((attributeCount, subsetCount))

        for name, timeValue in zip(algorithmNames, times):
            measurements[name].append(timeValue)

    for name in algorithmNames:
        plotTime(measurements[name], attributeSubsetCount, name, "KVAC_MEQ")

def plotTime(listOfTimes, attributeSubsetCount, algorithmName, schemeName):

    positions = range(len(attributeSubsetCount))
    timesMs = [timeValue * 1000 for timeValue in listOfTimes]
    labels = [f"({a}, {b})" for a, b in attributeSubsetCount]

    plt.figure()
    plt.plot(positions, timesMs, label=algorithmName)
    plt.xticks(positions, labels, rotation=20)
    plt.xlabel("(AttributeCount, SubsetCount)")
    plt.ylabel("Time (ms)")
    plt.legend()
    plt.grid()
    plt.savefig(
        f"/workspace/tests/benchmark/benchmark_Plots/{schemeName}_Plots/{algorithmName}.png",
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()