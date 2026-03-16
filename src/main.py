from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair

group = PairingGroup('SS512')

g1 = group.random(G1)
g2 = group.random(G2)
a = group.random(ZR)

result = pair(g1 ** a, g2)

print("Pairing works:", result)

# just checking lmao
