from charm.toolbox.pairinggroup import G1, ZR, pair


class SP_MAC_EQ:

    """
    Implementation of Structure-Preserving MAC on Equivalence classes (SP-MAC-EQ).
    This is described in section three of Keyed-Verification Anonymous Credentials with Highly Efficient Partial Disclosure.

    Notation in paper and our correlating naming scheme:
    - encodedMessageVector: M = (M_1, ..., M_l) where each M_i ∈ G1*.
    - secretKey: sk = (x_1, ..., x_l) where each x_i ∈ Z_p*.
    - randomScalarA (MAC randomness): a ∈ Z_p*.
    - tagR, tagT: τ = (R, T) where:
        R = a * (sum_i x_i M_i)
        T = a^(-1) * G2
        and R, T ∈ G1, G2.
    - randomScalarMu (scalar to change representation): μ ∈ Z_p*.
    - randomScalar (scalar for re-randomizing representation): ζ ∈ Z_p*.

    Implementation note:
    This class assumes message inputs (encodedMessageVector) have already been encoded as group elements in G1.
    In other words, hashing or encoding of the message components is assumed to be done externally.
    """

    def __init__(self, groupObject, g1Element, g2Element):

        """
        The initialization consists of storing the 2 fixed generators and the group context used in the scheme.

        Used by:
        The Issuer will initialize the SP_MAC_EQ scheme object.

        Notation in paper and our correlating naming scheme:
        - groupObject: The bilinear group of type-3 noted BG, which is returned by MEQ.SetupR(1^λ).
        - g1Element, g2Element: The two generators from respectively group G1 and G2.

        Why we do this:
        Since the SP-MAC-EQ scheme operates in an asymmetric bilinear group (G1 x G2 -> GT),
        we keep a reference to the group object to get random elements in ZR (Z_p*) and the base element in G1.
        We also keep a reference via import in the .py file to charm.toolbox.pairinggroup.pair
        for pairing operations (e: G1 x G2 -> GT).
        """

        self.group = groupObject
        self.g1 = g1Element
        self.g2 = g2Element


    def keyGen(self, length):

        """
        Generates the secret MAC key sk = (x_1, ..., x_l).

        Used by:
        - Issuer, when generating the secret key used for MAC creation and keyed verification.

        Notation in paper and our correlating naming scheme:
        - length: corresponds to l which is the number of message components.

        - keyGen() returns the secretKey: sk = (x_1, ..., x_l) where each x_i ∈ Z_p*.

        Why we do this:
        Each message component M_i is weighted by its own random scalar x_i which we generate through
        the group random and ZR import. This is used to ensure only systems which have access to the
        same secret key can compute the linear combination of scalar and message component (sum_i x_i M_i).

        Implementation detail:
        Random scalars in Z_p* are sampled through self.group.random(ZR).
        To ensure non-base elements, as the paper specifies Z_p*, we create a while loop around each random draw.
        This should almost never happen, but the Charm API does not seem to exclude the base element by default.
        """

        secretKey = []

        for _ in range(length):
            scalar = self.group.random(ZR)
            while scalar == self.group.init(ZR):
                scalar = self.group.random(ZR)
            secretKey.append(scalar)

        return secretKey

    def createMac(self, secretKey, encodedMessageVector, randomScalarA):

        """
        Creates a tag τ = (R, T) on a representative message vector M.

        Used by:
        - Issuer, when issuing a tag on the chosen representative message vector.

        Notation in paper and our correlating naming scheme:
        - secretKey: should be the sk = (x_1, ..., x_l) computed in keyGen().
        - encodedMessageVector: M = (M_1, ..., M_l) where each M_i ∈ G1* and M_i != 0_G1.
        - randomScalarA: the random scalar a ∈ Z_p*.

        - createMac() returns tagR and tagT: τ = (R, T).

        Why we do this:
        The tag is built around the weighted sum computed using the secret key and the message components (sum_i x_i M_i).
        Multiplying this weighted sum with our random scalar a randomizes and blinds the linear combination.
        We then compute a^(-1) * G2, which will later cancel out the randomness during verification,
        so the verifier can check validity through the pairing equation.
        Given the structure-preserving nature of this tag creation,
        we ensure that the representation can later be changed through the same equivalence class if needed.
        """

        # Compute the hidden linear combination sum_i x_i * M_i.
        weightedSum = self.computeWeightedSum(secretKey, encodedMessageVector)

        # Compute a^{-1}. This is needed for the second tag component tagT: T = a^{-1} * G2.
        randomScalarAInverse = randomScalarA ** -1

        # Create the two tags:
        # tagR: R = a * (sum_i x_i M_i)
        # tagT: T = a^{-1} * G2
        tagR = weightedSum * randomScalarA
        tagT = self.g2 * randomScalarAInverse

        return tagR, tagT


    def verify(self, secretKey, encodedMessageVector, tagR, tagT):

        """
        Verify whether the tag τ = (R, T) is valid for the message vector M.

        Used by:
        - Verifier / designated verifier, since verification in this scheme is keyed.
        - In the larger KVAC setting, this is the party that holds the secret key and checks validity.

        Notation in paper and our correlating naming scheme:
        - secretKey: should be the sk = (x_1, ..., x_l) computed in keyGen().
        - encodedMessageVector: M = (M_1, ..., M_l) where each M_i ∈ G1* and M_i != 0_G1.
        - tagR and tagT: τ = (R, T) where R, T should correspond to
          R = a * (sum_i x_i M_i) and T = a^{-1} * G2.

        - verify() returns a boolean corresponding to the verification requirement:
          e(sum_i x_i M_i, G2) = e(R, T)

        Why we do this:
        If the tag was generated by an honest party, then tagR and tagT will have been generated according to:
        R = a * (sum_i x_i M_i)
        T = a^{-1} * G2

        By cancelling the random element a ∈ Z_p* through the pairing process, we can verify the validity of:
        e(R, T) = e(a * (sum_i x_i M_i), a^{-1} * G2) = e(sum_i x_i M_i, G2).

        The function then returns the result of validity through a boolean.
        """

        # Compute the weighted sum (sum_i x_i * M_i)
        weightedSum = self.computeWeightedSum(secretKey, encodedMessageVector)

        # Check that no message M_i = 0_G1
        if weightedSum is None:
            return False

        # Cancel out the random scalar of the computed tags and given tags using pair() from Charm:
        # e(a * (sum_i x_i M_i), a^{-1} * G2)
        left = pair(weightedSum, self.g2)
        right = pair(tagR, tagT)

        # If the computed tags match the given tags, verification is successful.
        return left == right


    def changeRepresentation(self, encodedMessageVector, tagR, tagT, randomScalarMu):

        """
        Change the authenticated representative from M to μM and re-randomize the tag.

        Used by:
        - User / prover, when changing the representation of a valid message-tag pair
          before presenting it later in the protocol.

        Notation in paper and our correlating naming scheme:
        - encodedMessageVector: M = (M_1, ..., M_l) where each M_i ∈ G1*.
        - tagR and tagT: τ = (R, T) where R, T should correspond to
          R = a * (sum_i x_i M_i) and T = a^{-1} * G2.
        - randomScalarMu: corresponds to μ ∈ Z_p*
        - local randomScalar: corresponds to ζ ∈ Z_p*

        - changeRepresentation() returns the new message vector M' = μM and the new tag τ' = (R', T').
        - changedMessageVector: is the changed representation of the message vector using randomScalarMu (M' = μM).
        - newTagR, newTagT: is the corresponding tag to the changed message vector where
          τ' = (R', T') = (ζμR, ζ^(-1)T).

        Why we do this:
        Through the equivalence relation described in the paper we get: M' = μM.
        Given the encoding of the message vector into G1*,
        we know the initial representation (M) to be in the same equivalence class as the scaled message vector (M').
        This further allows for a valid tag on M to be changed into a valid tag for μM without knowledge of the secret key.
        As both the tag and message vector can have their representation changed to match using random scalars,
        it enables authentication over equivalence classes as opposed to authentication of only one fixed representative.
        The scalar ζ re-randomizes the tag, ensuring the "perfect adaptation of tags" property,
        where τ' follows the same distribution as a newly generated MAC tag on the transformed representative.
        """

        # Get random scalar ζ and ensuring ζ = Z_p*
        randomScalar = self.group.random(ZR)
        while randomScalar == self.group.init(ZR):
                randomScalar = self.group.random(ZR)

        # Change the encoded message vector to the mu representation
        changedMessageVector = [message * randomScalarMu for message in encodedMessageVector]

        # Randomize using the scalar and mu to match the changed messages while preserving distribution
        newTagR = tagR * (randomScalar * randomScalarMu)
        newTagT = tagT * (randomScalar ** -1)

        # Return new representation
        return changedMessageVector, newTagR, newTagT


    def computeWeightedSum(self, secretKey, encodedMessageVector):

        """
        Computes the hidden linear combination sum_i x_i M_i.

        Used by:
        - Issuer internally during createMac().
        - Verifier internally during verify().

        Notation in paper and our correlating naming scheme:
        - secretKey: should be the sk = (x_1, ..., x_l) computed in keyGen().
        - encodedMessageVector: M = (M_1, ..., M_l) where each M_i ∈ G1*.

        - computeWeightedSum() returns the corresponding linear combination: sum_i x_i M_i

        Why we do this:
        computeWeightedSum() is a helper function used in createMac() and verify().
        When creating the MAC tag and when verifying, we need the linear combination of our
        messages and secret key. Under MAC tag creation, the linear sum will be scaled by a random scalar a ∈ Z_p*.
        When the method is later used through verify(), the linear combination is checked through the pairing equation.

        Implementation detail:
        The verification requires that no message corresponds to the base element of the group (M_i != 0_G1).
        If this happens, the weighted sum will be returned as None.
        """

        # Get the base element in G1
        baseElement = self.group.init(G1)
        weightedSum = baseElement

        # Create linear combination sum_i x_i M_i.
        # For each message, check that it is not the base element (M_i = 0_G1). If yes, return None.
        for i in range(len(secretKey)):
            if encodedMessageVector[i] == baseElement:
                return None
            weightedSum += encodedMessageVector[i] * secretKey[i]

        return weightedSum