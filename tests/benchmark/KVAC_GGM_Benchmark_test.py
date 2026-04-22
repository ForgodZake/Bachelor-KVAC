from charm.toolbox.ecgroup import ECGroup, ZR
from charm.toolbox.eccurve import secp256k1
from KVAC_GGM_Scheme import KVAC_GGM
import matplotlib.pyplot as plt
import pytest
import time



@pytest.fixture
def group():
    return ECGroup(secp256k1)


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
    scheme = KVAC_GGM(group)
    times = []

    attributeList = buildAttributeList(attributeCount)
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

    credentialSizeKiB = (sizeBytes(tag, group) + sizeBytes(basis, group)) / 1024
    presentationSizeKiB = (sizeBytes(randomizedTag, group) + sizeBytes(witness, group)) / 1024

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


def test_KVAC_GGM_benchmarks(group):

    print("")
    print("")
    print("KVAC_GGM Bencmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    algorithmNames = ["keyGen", "issueCred", "obtainCred", "showCred", "verify"]
    measurements = {name: [] for name in algorithmNames}
    attributeSubsetCount = []

    for attributeCount, subsetCount in benchmarkSizes:
        times = runBenchmark(attributeCount, subsetCount, group)
        attributeSubsetCount.append((attributeCount, subsetCount))

        for name, timeValue in zip(algorithmNames, times):
            measurements[name].append(timeValue)

    for name in algorithmNames:
        plotTime(measurements[name], attributeSubsetCount, name, "KVAC_GGM")

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