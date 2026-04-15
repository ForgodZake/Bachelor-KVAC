from charm.toolbox.pairinggroup import PairingGroup
from KVAC_MEQ_Scheme import KVAC_MEQ
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
    scheme = KVAC_MEQ(group)
    times = []

    attributeList = buildAttributeList(attributeCount)
    attributeSubsetList = attributeList[:subsetCount]

    start = time.perf_counter()
    isk, ipar = scheme.keyGen(len(attributeList))
    end = time.perf_counter()
    times.append(end - start)

    ipar_MEQ, ipar_DVSC = ipar
    challenge, response, commitmentBasis = ipar_DVSC

    assert scheme.SchemeDVSC.verifyIssuerParameter(challenge, response, commitmentBasis)
    
    start = time.perf_counter()
    tagR, tagT, response, encodedMessages, _ = scheme.issueCred(
        attributeList, isk, ipar_DVSC, ipar_MEQ
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    tagR, tagT = scheme.obtainCred(
        attributeList, ipar_DVSC, ipar_MEQ, response, tagR, tagT, False
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    randomizedTag, randomizedCommitment, witness = scheme.showCred(
        tagR, tagT, attributeList, attributeSubsetList, encodedMessages, ipar_DVSC
    )
    end = time.perf_counter()
    times.append(end - start)

    start = time.perf_counter()
    _ = scheme.verify(
        randomizedTag, randomizedCommitment, witness, attributeSubsetList, isk
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


def test_KVAC_MEQ_benchmarks(group):

    print("")
    print("")
    print("KVAC_MEQ Bencmarks:")

    benchmarkSizes = [
        (2**4, 2**3),
        (2**6, 2**5),
        (2**8, 2**7),
        (2**10, 2**9),
        (2**12, 2**11),
    ]

    for attributeCount, subsetCount in benchmarkSizes:
        runBenchmark(attributeCount, subsetCount, group)