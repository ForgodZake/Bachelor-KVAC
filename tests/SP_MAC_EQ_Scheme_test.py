from charm.toolbox.pairinggroup import PairingGroup, ZR
from SP_MAC_EQ_Scheme import SP_MAC_EQ
import pytest

@pytest.fixture
def group():
    return PairingGroup('SS512')

@pytest.fixture
def scheme(group):
    return SP_MAC_EQ(group)

@pytest.fixture
def attributes():
    return ["18", "Danish", "Plumber"]

def test_mac_verifies_correctly(scheme, attributes):

    secretKey = scheme.keyGen(len(attributes))

    encodedMessages, tagR, tagT = scheme.createMac(secretKey, attributes)

    assert scheme.verify(secretKey, encodedMessages, tagR, tagT)


def test_changed_representation_also_verifies(group, scheme, attributes):

    
    secretKey = scheme.keyGen(len(attributes))

    encodedMessages, tagR, tagT = scheme.createMac(secretKey, attributes)

    mu = group.random(ZR)

    changedMessages, newTagR, newTagT = scheme.changeRepresentation(
        encodedMessages, tagR, tagT, mu
    )

    assert scheme.verify(secretKey, changedMessages, newTagR, newTagT)