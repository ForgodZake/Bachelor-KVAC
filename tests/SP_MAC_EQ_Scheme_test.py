from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
from SP_MAC_EQ_Scheme import SP_MAC_EQ
import pytest

@pytest.fixture
def group():
    return PairingGroup('SS512')

@pytest.fixture
def scheme(group):
    g1 = group.random(G1)
    g2 = group.random(G2)
    return SP_MAC_EQ(group, g1, g2)

@pytest.fixture
def attributes():
    return ["18", "Danish", "Plumber"]

@pytest.fixture
def randomScalar(group):
    return group.random(ZR)

def test_mac_verifies_correctly(group, scheme, attributes, randomScalar):

    secretKey = scheme.keyGen(len(attributes))

    # the raw message string, is hashed via the group hash to introduce randomness, 
    # The hash is implicity matched to an element in G1 via charm algorithm.
    encodedMessages = [group.hash(message, G1) for message in attributes]

    encodedMessages, tagR, tagT = scheme.createMac(secretKey, encodedMessages, randomScalar)

    assert scheme.verify(secretKey, encodedMessages, tagR, tagT)


def test_changed_representation_also_verifies(group, scheme, attributes, randomScalar):

    
    secretKey = scheme.keyGen(len(attributes))

    encodedMessages = [group.hash(message, G1) for message in attributes]

    encodedMessages, tagR, tagT = scheme.createMac(secretKey, encodedMessages, randomScalar)

    mu = group.random(ZR)

    changedMessages, newTagR, newTagT = scheme.changeRepresentation(
        encodedMessages, tagR, tagT, mu
    )

    assert scheme.verify(secretKey, changedMessages, newTagR, newTagT)