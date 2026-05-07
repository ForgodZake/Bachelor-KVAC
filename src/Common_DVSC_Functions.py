from charm.toolbox.pairinggroup import G1, ZR as PAIRING_ZR
from charm.toolbox.ecgroup import G, ZR as EC_ZR


class Common_DVSC_Functions:

    """
    Contains a set of functions which are used in DVSC but also had usecase in KVAC_GGM.
    
    Implementation note: 
    The function mostly consist of setup and helperfunctions with one exception of the openSubset() fuction,
    which is part of the DVSC scheme, but, with minor changes, can be utilized in KVAC_GGM as well.
    """

    def __init__(self, groupObject, generator=None):

        """
        Store the group context, detect the active group setting, and initialize the base generator.

        Why we do this:
        Since the KVAC_GGM and KVAC_MEQ scheme works of different charm groups, elliptic curves and pairing groups respectively,
        the init detects the usecase and initializes group elements and scalar types accordingly.

        generator can either be provided or not dependent on whether it's the MEQ or GGM initialization,
        since MEQ needs it externally of the DVSC scheme.
        """
        
        self.group = groupObject
        self.groupSetting = self.group.groupSetting()

        if self.groupSetting == "elliptic_curve":
            self.groupElementType = G
            self.scalarType = EC_ZR
            self.gPrime = self.group.random(self.groupElementType)
        else:
            self.groupElementType = G1
            self.scalarType = PAIRING_ZR

        if generator is None:
            self.g1 = self.group.random(self.groupElementType)
        else:
            self.g1 = generator

    """
    groupIdentity(), scalarZero(), scalarOne(), groupMult(), gropuAdd(), gropSub() are a set if helper functions, 
    which changes the way group operations are computed as GGM assumes mulitplicative and MEQ additative.
    This specification is due to charms api differences when working on elliptic curves respectively to pairing groups.
    
    """
    def groupIdentity(self):
        return self.group.init(self.groupElementType)
    

    def scalarZero(self):
        return self.group.init(self.scalarType)


    def scalarOne(self):
        return self.group.init(self.scalarType, 1) 
    

    def groupMult(self, element, scalar):
        if self.groupSetting == "elliptic_curve":
            return element ** scalar
        return element * scalar
    

    def groupAdd(self, element, scalar):
        if self.groupSetting == "elliptic_curve":
            return element * scalar
        return element + scalar
    

    def groupSub(self, element, scalar):
        if self.groupSetting == "elliptic_curve":
            return element / scalar
        return element - scalar


    def createPolynomial(self, disclosedAttributes):

        """
        A helper function which Contructs the polynomial f_S(X) = ∏_{s ∈ S}(X - s), and returns the coefficients.

        Notation in paper and our correlating naming scheme:
        - disclosedAttributes: corresponds to the subset S, represented as already hashed field elements in Z_p.
        - returned coefficients: corresponds to the coefficient list (f_0, ..., f_|S|).

        Why we do this:
        The attributes conainted in the set S is represented through the polynomial,
        and is used to together with the commitment basis when creating a commitment.
        """
        
        coefficients = [1]

        # for each attribute we update the polynomial degree,
        # by doing currentPoly * (X - a)
        for attribute in disclosedAttributes:
            # Set the length of the next degree poly
            newCoefficients = [0] * (len(coefficients) + 1)
            
            # Update all the coefficients by currentPoly * (X - a)
            for i in range(len(coefficients)):
                newCoefficients[i] += -attribute * coefficients[i]
                newCoefficients[i + 1] += coefficients[i]

            # store and repeat
            coefficients = newCoefficients

        return coefficients


    def evaluatePolynomial(self, disclosedAttributes, secretKey):

        """
        Evaluates the polynomial directly from the disclosed subset as the secret v is known.

        Notation in paper and our correlating naming scheme:
        - disclosedAttributes: is the corresponding set S of attributes hashed to Z_p.
        - secretKey: sk = v where v ∈ Z_p*.

        Why we do this:
        As both issuer and verifier knows the secret v, they dont need to create and evaluate the polynomial.
        They can evaluate it directly on the disclosedAttributes by using the secret key directly: f_D(v) = ∏_{d ∈ D}(v - d).

        """

        result = self.scalarOne()

        # evaluate f_S(v) without computing polynomial as we have access to secretKey
        for attribute in disclosedAttributes:
            result *= (secretKey - attribute)

        return result
        
    
    def openSubset(self, commitmentBasis, disclosedAttributes, requiredAttributeSubset, randomScalarMu):

        """
        Computes the witness  W = μf_{S\D}(v)G.

        Used by:
        - User uses openSubset() when creating witness for verification of commitment.

        Notation in paper and our correlating naming scheme:
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G.
        - disclosedAttributes: is the corresponding set S of attributes hashed to Z_p.
        - requiredAttributeSubset: is the corresponding set D ⊆ S of attributes hashed to Z_p.
        - randomScalarMu: μ ∈ Z_p*.
        
        - returns the witness:  W = μf_{S\D}(v)G.

        Why we do this:
        To open only the subset for a verifier the remaining set S\D is used to construct the witness.
        This works as f_S(X) = f_D(X) f_{S\D}(X),
        making it possible for the verifier to recompute the commitment together with f_D(v).
        """

        remainingAttributes = []
        # Create the set without the subset (S / D)
        for i in range(len(disclosedAttributes)):
            if not (disclosedAttributes[i] in requiredAttributeSubset):
                remainingAttributes.append(disclosedAttributes[i])

        # Hash the remaining attributes (needed as they are strings) and create the polynomial
        coefficients = self.createPolynomial(remainingAttributes)

        # Create the witness by scaling the commitment with our random mu
        witness = self.groupMult(self.createCommitment(coefficients, commitmentBasis), randomScalarMu)

        return witness
    

    def createCommitment(self, coefficients, commitmentBasis):

        """
        creatCommitment() computes the polynomial as the secret v using the commitment basis: f(v)G = Σ_i f_i V_i.
        
        Notation in paper and our correlating naming scheme:
        - coefficients: corresponds to the coefficients (f_i) of the polynomial f(X).
        - commitmentBasis: is part of the issuers public parameters (ipar) corresponding to (V_0, ..., V_t) where V_i = v^i * G.

        Why we do this:
        This is the computation done by user, where the secret v is unknown.
        The commitmentBasis is used instead by and computes the polynomial at v via  V_i = v^i G,
        and the function evaluated at v corresonds to f(v)G = Σ_i f_i V_i.
        
        """

        commitment = self.groupIdentity()

        # create commitment by scaling each basis element by the coefficient (f_i * V_i)
        for i in range(len(coefficients)):
            commitment = self.groupAdd(self.groupMult(commitmentBasis[i], coefficients[i]), commitment)

        return commitment
    

    def hashForChallenge(self, announcementSequence):

        """
        Hashes a given announcementSequence by creating a byte representation and serializing it,
        then hasing it to the required scalarType so it computationally works in the challenge.
        As some elements are contained within tuples and list, hashforChallenge() uses toBytes,
        which recursively accesses each element if part of a data structure. 
        """

        # convert announcement to byterepresentation for hashing
        byteRepresentation = self.toBytes(announcementSequence)

        return self.group.hash(byteRepresentation, self.scalarType)
    

    def toBytes(self, announcementSequence):

        """
        Recursively transforms the announcementSequence in to a serialized byte representation.
        """

        # If announcementSequence is string encode 
        if isinstance(announcementSequence, str):
            return announcementSequence.encode("utf-8")

        # If announcementSequence is list or tuble recursively access each element,
        # and concatenate encoding/serialization to result.
        if isinstance(announcementSequence, (list, tuple)):
            parts = []
            for item in announcementSequence:
                parts.append(self.toBytes(item))
            return b"||".join(parts)

        # Otherwise serialize elements from group objects (G1, G2, ZR elements)
        return self.group.serialize(announcementSequence)
    