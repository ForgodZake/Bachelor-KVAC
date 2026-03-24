from charm.toolbox.pairinggroup import PairingGroup, ZR
from SP_MAC_EQ_Scheme import SP_MAC_EQ


def test_mac_verifies_correctly():
    group = PairingGroup('SS512')
    scheme = SP_MAC_EQ(group)

    attributes = ["18", "Danish", "Plumber"]
    secret_key = scheme.keyGen(len(attributes))

    encoded_messages, tag_r, tag_t = scheme.createMac(secret_key, attributes)

    assert scheme.verify(secret_key, encoded_messages, tag_r, tag_t)


def test_changed_representation_also_verifies():
    group = PairingGroup('SS512')
    scheme = SP_MAC_EQ(group)

    attributes = ["18", "Danish", "Plumber"]
    secret_key = scheme.keyGen(len(attributes))

    encoded_messages, tag_r, tag_t = scheme.createMac(secret_key, attributes)

    mu = group.random(ZR)
    changed_messages, new_tag_r, new_tag_t = scheme.changeRepresentation(
        encoded_messages, tag_r, tag_t, mu
    )

    assert scheme.verify(secret_key, changed_messages, new_tag_r, new_tag_t)