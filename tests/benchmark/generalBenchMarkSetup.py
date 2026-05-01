import matplotlib.pyplot as plt
import pytest


def getTestSetup(benchmarkSizes, group, runBenchmark, algorithmNames):

    measurements = {name: [] for name in algorithmNames}
    attributeSubsetCount = []

    for attributeCount, subsetCount in benchmarkSizes:
        times = runBenchmark(attributeCount, subsetCount, group)
        attributeSubsetCount.append((attributeCount, subsetCount))

        for name, timeValue in zip(algorithmNames, times):
            measurements[name].append(timeValue)

    return algorithmNames, measurements, attributeSubsetCount


def plotTime(listOfTimes, attributeSubsetCount, algorithmName, schemeName, testType):

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
        f"/workspace/tests/benchmark/benchmark_Plots/{schemeName}_Plots/{algorithmName}{testType}.png",
        dpi=300,
        bbox_inches="tight"
    )
    plt.close()


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