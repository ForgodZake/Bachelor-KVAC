from charm.toolbox.pairinggroup import ZR, PairingGroup
from KVAC_GGM_Scheme import KVAC_GGM
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
    scheme = KVAC_GGM(group)
    times = []

    attributeList = buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]

    start = time.perf_counter()
    isk, ipar = scheme.keyGen()
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tag, basis, pi = scheme.issueCred(attributeList, isk, ipar)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tag, basis = scheme.obtainCred(tag, basis, pi, attributeList, ipar)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    randomizedTag, witness = scheme.showCred(tag, basis, attributeList, attributeSubsetList)
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verify(randomizedTag, witness, attributeSubsetList, isk)
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

    for attributeCount, subsetCount in benchmarkSizes:
        runBenchmark(attributeCount, subsetCount, group)