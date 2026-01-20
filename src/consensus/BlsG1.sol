// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title BlsG1 Proof of Possession Library
/// @notice Utility to perform proof of possessions for BLS12-381 using EIP2537
/// @dev Implements the 'min-sig' variant (Signatures in G1, Public Keys in G2)
/// @author Robriks 📯️📯️📯️.eth

library BlsG1 {
    /// @dev Represents a field element in BLS12-381 base field Fp
    /// @param data The 64-byte field element data padded with 16 zero bytes for EIP2537 compliance
    struct Fp {
        bytes data;
    }

    /// @dev Represents a proof of possession for a validator's BLS public key
    /// @param uncompressedPubkey A 192-byte uncompressed G2 point
    /// @param uncompressedSignature A 96-byte uncompressed G1 point PoP over the `proofOfPossessionMessage()`
    /// @notice Ensuring `uncompressedPubkey` corresponds to `ValidatorInfo::blsPubkey` is better
    /// performed externally in Rust by the protocol due to EIP2537 precompile & EVM limitations
    /// so this contract does not perform any (un)compression checks
    struct ProofOfPossession {
        bytes uncompressedPubkey;
        bytes uncompressedSignature;
    }

    error InvalidPoint(uint256 actualLen, uint256 expectedLen);
    error InvalidPadding();
    error InvalidBLSPubkey();
    error InvalidUncompressedBLSPubkey();
    error InvalidFpOffset();
    error InvalidBLSProof();
    error EllTooLarge(uint256 ell);
    error LengthTooLarge(uint256 len);
    error CountTooLarge(uint256 count);
    error DSTTooLong(uint256 dstLen);
    error I2OSPIntegerTooLarge(uint256 i2ospInteger);
    error LowLevelCallFailure(bytes err);

    /// @dev Relevant BLS12-381 precompiles
    address public constant G1_ADD = address(0x0B);
    address public constant G1_MUL = address(0x0C);
    address public constant G2_ADD = address(0x0D);
    address public constant G2_MUL = address(0x0E);
    address public constant PAIRING_CHECK = address(0x0F);
    address public constant MAP_FP_TO_G1 = address(0x10);

    /// @dev Standard BLS12-381 Generator Points (EIP-2537 encoded)
    /// @notice These are the standard generators, useful for deriving public keys from secrets in tests
    bytes public constant G1_GENERATOR = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes public constant G2_GENERATOR = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    /// @dev Negation of the BLS12-381 `G2_GENERATOR` point, used for signature pairing checks in our PoP
    bytes public constant G2_GENERATOR_NEG =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
    
    /// @dev 381-bit base field prime modulus
    bytes public constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    
    /// @dev The BLS12-381 identity elements (infinity/zero points) encoded to comply with EIP2537
    bytes public constant G1_IDENTITY = new bytes(EIP2537_G1_POINT_SIZE);
    bytes public constant G2_IDENTITY = new bytes(EIP2537_G2_POINT_SIZE);

    /// @dev The Standard DST for BLS12-381 G1 Basic Signatures (RFC 9380/9677)
    /// https://datatracker.ietf.org/doc/html/rfc9380#appendix-J.9.1
    /// @notice This is the generic default used by `blst::min_sig`. Integrators should consider custom DST.
    bytes public constant HASH_TO_G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    /// @dev Constants for `expand_message_xmd` variant defined in RFC9380
    uint256 public constant B_IN_BYTES = 32; // output size in bytes by compliant hash fn (sha256)
    uint256 public constant S_IN_BYTES = 64; // block size in bytes by compliant hash fn (sha256)

    /// @dev L parameter from RFC 9380 for hash-to-field operations
    /// guarantees proper statistical distribution in hash-to-field operations
    /// L = ceil((ceil(log2(p)) + k) / 8) where:
    /// - p is the BLS12-381 field modulus (381 bits)
    /// - k is the security parameter (128 bits)
    /// - L = ceil((381 + 128) / 8) = ceil(509 / 8) = 64 bytes
    uint256 public constant L = 64;

    /// @dev Actual size of BLS12-381 field elements in bytes (381 bits = 48 bytes)
    uint256 public constant FIELD_ELEMENT_SIZE = 48;
    /// @dev EIP-2537 encoding sizes
    uint256 public constant EIP2537_FIELD_ELEMENT_SIZE = 64;
    uint256 public constant EIP2537_G1_POINT_SIZE = 128;
    uint256 public constant EIP2537_G2_POINT_SIZE = 256;

    /// @dev Encode a BLS12-381 G1 point (signature for min_sig) to EIP2537 format (128 bytes)
    /// @param uncompressedSignature 96-byte uncompressed G1 point
    /// @return _ EIP2537-compliant, 128-byte encoded G1 point comprising two 64-byte padded field elements (x, y
    /// coordinates)
    function encodeG1PointForEIP2537(bytes memory uncompressedSignature) external pure returns (bytes memory) {
        if (uncompressedSignature.length != 96) {
            revert InvalidBLSProof();
        }

        // if the provided signature is the identity, return early with 128 zero bytes
        bytes memory encoded = new bytes(EIP2537_G1_POINT_SIZE);
        if (isInfinityPointG1(uncompressedSignature)) return encoded;

        // otherwise, pad x and y coordinates with 16 leading zeroes
        fieldElementToEIP2537Bytes(uncompressedSignature, 0, encoded, 0);
        fieldElementToEIP2537Bytes(uncompressedSignature, 48, encoded, 64);

        return encoded;
    }

    /// @dev Decodes an EIP2537-encoded G1 point (128 bytes) to uncompressed format (96 bytes)
    /// @param encodedPoint 128-byte EIP2537 encoded G1 point
    /// @return uncompressed 96-byte uncompressed G1 point
    function decodeG1PointFromEIP2537(bytes memory encodedPoint) external pure returns (bytes memory) {
        if (encodedPoint.length != EIP2537_G1_POINT_SIZE) {
            revert InvalidPoint(encodedPoint.length, EIP2537_G1_POINT_SIZE);
        }

        bytes memory uncompressed = new bytes(96);
        
        // Extract X
        eip2537BytesToFieldElement(encodedPoint, 0, uncompressed, 0);
        // Extract Y
        eip2537BytesToFieldElement(encodedPoint, 64, uncompressed, 48);

        return uncompressed;
    }

    /// @dev Encode a BLS12-381 G2 point (public key for min_sig) to EIP2537 format (256 bytes)
    /// @param uncompressedPubkey 192-byte uncompressed G2 point
    /// @return _ EIP2537-compliant, 256-byte encoded G1 point comprising four 64-byte padded field elements (x, y
    /// coordinates)
    /// @notice Coordinate reordering is performed because EIP2537 precompiles expect: `x.c0 || x.c1 || y.c0 || y.c1`
    /// This differs from some bls libraries (such as blst used by TN) which serialize to `x.c1 || x.c0 || y.c1 || y.c0`
    function encodeG2PointForEIP2537(bytes memory uncompressedPubkey) external pure returns (bytes memory) {
        if (uncompressedPubkey.length != 192) {
            revert InvalidUncompressedBLSPubkey();
        }

        // if the provided public key is the identity, return early with 256 zero bytes
        bytes memory encoded = new bytes(EIP2537_G2_POINT_SIZE);
        if (isInfinityPointG2(uncompressedPubkey)) return encoded;

        // reorder blst serialization of coordinates for EIP2537 compliance: `x.c0 || x.c1 || y.c0 || y.c1`
        // x.c0 (second 48 bytes of x coordinate, bytes 48-96)
        fieldElementToEIP2537Bytes(uncompressedPubkey, 48, encoded, 0);
        // x.c1 (first 48 bytes of x, bytes 0-48)
        fieldElementToEIP2537Bytes(uncompressedPubkey, 0, encoded, 64);
        // y.c0 (second 48 bytes of y, bytes 144-192)
        fieldElementToEIP2537Bytes(uncompressedPubkey, 144, encoded, 128);
        // y.c1 (first 48 bytes of y, bytes 96-144)
        fieldElementToEIP2537Bytes(uncompressedPubkey, 96, encoded, 192);

        return encoded;
    }

    /// @dev Decodes an EIP2537-encoded G2 point (256 bytes) to uncompressed format (192 bytes)
    /// @notice Reverses the coordinate reordering (x.c0/c1 -> x.c1/c0) used in encoding
    function decodeG2PointFromEIP2537(bytes memory encodedPoint) external pure returns (bytes memory) {
        if (encodedPoint.length != EIP2537_G2_POINT_SIZE) {
            revert InvalidPoint(encodedPoint.length, EIP2537_G2_POINT_SIZE);
        }

        bytes memory uncompressed = new bytes(192);
        
        // x.c1 (bytes 0-48 in uncompressed) comes from 2nd element (bytes 64-128 in encoded)
        eip2537BytesToFieldElement(encodedPoint, 64, uncompressed, 0);
        
        // x.c0 (bytes 48-96 in uncompressed) comes from 1st element (bytes 0-64 in encoded)
        eip2537BytesToFieldElement(encodedPoint, 0, uncompressed, 48);

        // y.c1 (bytes 96-144 in uncompressed) comes from 4th element (bytes 192-256 in encoded)
        eip2537BytesToFieldElement(encodedPoint, 192, uncompressed, 96);
        
        // y.c0 (bytes 144-192 in uncompressed) comes from 3rd element (bytes 128-192 in encoded)
        eip2537BytesToFieldElement(encodedPoint, 128, uncompressed, 144);

        return uncompressed;
    }

    /// @dev Validates an EIP2537-compliant G1 point by adding it to the identity using G1_ADD
    /// @return _ False if not 128 bytes in length, is not on the curve, or is the identity point
    function validatePointG1(bytes memory point) external view returns (bool) {
        if (point.length != EIP2537_G1_POINT_SIZE || isInfinityPointG1(point)) {
            revert InvalidPoint(point.length, EIP2537_G1_POINT_SIZE);
        }
        return bytesEq(addG1(point, G1_IDENTITY), point);
    }

    /// @dev Validates an EIP2537-compliant G2 point by adding it to the identity using G2_ADD
    /// @return _ False if not 256 bytes in length, is not on the curve, or is the identity point
    function validatePointG2(bytes memory point) external view returns (bool) {
        if (point.length != EIP2537_G2_POINT_SIZE || isInfinityPointG2(point)) {
            revert InvalidPoint(point.length, EIP2537_G2_POINT_SIZE);
        }
        return bytesEq(addG2(point, G2_IDENTITY), point);
    }

    /// @dev Checks if an EIP2537-compliant G1 point is the identity (infinity/zero point)
    /// @param uncompressedPointG1 Is not validated to be a G1 point on the curve; this must be enforced separately
    function isInfinityPointG1(bytes memory uncompressedPointG1) public pure returns (bool) {
        return bytesEq(uncompressedPointG1, G1_IDENTITY);
    }

    /// @dev Checks if an EIP2537-compliant G2 point is the identity (infinity/zero point)
    /// @param uncompressedPointG2 Is not validated to be a G2 point on the curve; this must be enforced separately
    function isInfinityPointG2(bytes memory uncompressedPointG2) public pure returns (bool) {
        return bytesEq(uncompressedPointG2, G2_IDENTITY);
    }

    /// @dev Checks if bytes `a == b`
    function bytesEq(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    /**
     * @notice Provided parameters must be uncompressed and EIP2537-compliant due to BLS12-381 precompile limitations
     * Using G2 group for public keys (256bytes for EIP2537) and G1 group for signature (128bytes for EIP2537)
     * Validators must sign over `prefixA || BLS pubkey || prefixB || validatorAddress` to ensure possession
     * Where `prefixA = POP_INTENT_PREFIX && prefixB = ADDRESS_LEN_PREFIX` (constants inserted by rust protocol
     * encoding)

    /**
     * @notice Verifies a Proof of Possession for a generic message using a custom DST
     * @param blsPubkey Using G2 group for public keys (256 bytes when EIP2537-encoded)
     * @param signature Using G1 group for signatures (128bytes when EIP2537-encoded)
     * @param message The raw message that was signed (pre-hashing).
     * eg for a PoP: `message = concat(validatorAddress, blsPubkey)`
     * @param dst The Domain Separator Tag to use for hashing the message to G1
     */
    function verifyProofOfPossessionG1(
        bytes memory blsPubkey,
        bytes memory signature,
        bytes memory message,
        bytes memory dst
    )
        external
        view
        returns (bool)
    {
        // EIP2537 precompiles handle byte length and curve validity checks so only check identity
        if (isInfinityPointG2(blsPubkey)) revert InvalidBLSPubkey();
        if (isInfinityPointG1(signature)) revert InvalidBLSProof();

        // hash message to G1 curve using the RFC9380 hash-to-curve spec
        bytes memory messagePointHash = hashToG1(message, dst);
        // check BLS signature using PAIRING_CHECK precompile
        bytes memory input = bytes.concat(messagePointHash, blsPubkey, signature, G2_GENERATOR_NEG);
        // EIP2537 pairing precompile enforces valid points
        (bool r, bytes memory res) = PAIRING_CHECK.staticcall(input);
        if (!r) revert LowLevelCallFailure(res);

        /// @dev Pairing check precompile returns single EVM word
        return uint256(bytes32(res)) == 1;
    }

    /// @dev Hash to a point on the G1 curve using hash-to-curve method outlined by RFC9380::8.8.1
    /// https://datatracker.ietf.org/doc/html/rfc9380#section-3-4.2.1
    /// @return _ The deterministic point on G1 curve derived from `message`
    function hashToG1(bytes memory message, bytes memory dst) public view returns (bytes memory) {
        // hash message with domain separator to obtain two field elements in the BLS12-381 base field:
        Fp[] memory fieldElements = hashToField(message, dst, 2);
        // map each fp field element to a point on the G1 curve using the MAP_FP_TO_G1 precompile:
        bytes memory point0 = mapFieldElementToG1(fieldElements[0]);
        bytes memory point1 = mapFieldElementToG1(fieldElements[1]);

        // get the msg point hash by adding the two resulting G1 curve points using the G1_ADD precompile
        return addG1(point0, point1);
    }

    /// @dev Maps a field element to a point on the G1 curve using the map-to-curve precompile
    /// @param element The field element to map
    /// @return _ The mapped G1 point
    function mapFieldElementToG1(Fp memory element) public view returns (bytes memory) {
        (bool r, bytes memory res) = MAP_FP_TO_G1.staticcall(element.data);
        if (!r) revert LowLevelCallFailure(res);

        return res;
    }

    /// @dev Adds two G1 curve points using the G1 addition precompile
    /// @return _ The G1 point addition result
    function addG1(bytes memory point0, bytes memory point1) public view returns (bytes memory) {
        (bool r, bytes memory res) = G1_ADD.staticcall(bytes.concat(point0, point1));
        if (!r) revert LowLevelCallFailure(res);

        return res;
    }

    /// @dev Adds two G2 curve points using the G2 addition precompile
    /// @return _ The G2 point addition result
    function addG2(bytes memory point0, bytes memory point1) public view returns (bytes memory) {
        (bool r, bytes memory res) = BlsG1.G2_ADD.staticcall(bytes.concat(point0, point1));
        if (!r) revert BlsG1.LowLevelCallFailure(res);

        return res;
    }

    /// @dev Scalar multiply the G1 curve point using the `G1_MUL` precompile
    /// @return _ The resulting G1 point after scalar multiplication
    function scalarMulG1(bytes memory g1Point, uint256 scalar) public view returns (bytes memory) {
        bytes memory input = bytes.concat(g1Point, bytes32(scalar));
        (bool r, bytes memory res) = G1_MUL.staticcall(input);
        if (!r) revert LowLevelCallFailure(res);

        return res;
    }

    /// @dev Scalar multiply the G2 curve point using the `G2_MUL` precompile
    /// @return _ The resulting G2 point after scalar multiplication
    function scalarMulG2(bytes memory g2Point, uint256 scalar) public view returns (bytes memory) {
        bytes memory input = bytes.concat(g2Point, bytes32(scalar));
        (bool r, bytes memory res) = G2_MUL.staticcall(input);
        if (!r) revert LowLevelCallFailure(res);

        return res;
    }

    /// @dev Hash input bytes to field element(s) in BLS12-381 base field Fp as outlined by RFC9380::5.2
    /// https://datatracker.ietf.org/doc/html/rfc9380#name-hash_to_field-implementation
    /// @notice Extension degree of field `m = 1` thus simpler `sgn0_m_eq_1(x)` applies
    /// @param input The value to hash
    /// @param dst Domain separator tag to prevent collisions between different hash usages
    /// @param count The number of field elements to generate
    /// @return _ Resulting field elements array
    function hashToField(bytes memory input, bytes memory dst, uint256 count) public view returns (Fp[] memory) {
        Fp[] memory result = new Fp[](count);
        // supports up to 1023 field elements although we only use 2 for PoP
        if (count > type(uint16).max / L) revert CountTooLarge(count);
        // `len_in_bytes = count * m * L`
        uint16 bytesLen = uint16(count * L);
        // `uniform_bytes = expand_message(msg, DST, len_in_bytes)`
        bytes memory uniformBytes = expandMessageXmd(input, dst, bytesLen);
        for (uint256 i; i < count; i++) {
            result[i] = processFieldElement(uniformBytes, i);
        }

        return result;
    }

    /// @notice Expands a message using the expand_message_xmd method as per RFC9380::5.3.1
    /// https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd
    /// @param message The input message as bytes
    /// @param dst The domain separation tag as string of at most 255 bytes
    /// @param outputLen The desired output length of the expanded message bytes
    /// @return result The expanded message as bytes
    function expandMessageXmd(
        bytes memory message,
        bytes memory dst,
        uint16 outputLen
    )
        public
        pure
        returns (bytes memory result)
    {
        // ell = ceil(len_in_bytes / b_in_bytes)
        uint256 ell = (outputLen + B_IN_BYTES - 1) / B_IN_BYTES;

        // ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
        if (ell > type(uint8).max) revert EllTooLarge(ell);
        if (outputLen > type(uint16).max) revert LengthTooLarge(outputLen);
        if (bytes(dst).length > type(uint8).max) revert DSTTooLong(bytes(dst).length);

        bytes memory dstPrime;
        bytes32 b0;
        {
            // DST_prime = DST || I2OSP(len(DST), 1)
            bytes memory dstBytes = bytes(dst);
            dstPrime = bytes.concat(dstBytes, I2OSP(dstBytes.length, 1));

            // Z_pad = I2OSP(0, s_in_bytes)
            // l_i_b_str = I2OSP(len_in_bytes, 2)
            bytes memory Z_pad = I2OSP(0, S_IN_BYTES);
            bytes memory l_i_b_str = I2OSP(uint256(outputLen), 2);

            // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || dstPrime
            bytes memory msgPrime = bytes.concat(Z_pad, message, l_i_b_str, I2OSP(0, 1), dstPrime);

            // b_0 = H(msg_prime)
            b0 = sha256(msgPrime);
        }

        {
            // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
            bytes32 b1 = sha256(abi.encodePacked(b0, I2OSP(1, 1), dstPrime));

            // produce uniformly random byte string ie `uniform_bytes = b_1 || ..b_i.. || b_ell`
            bytes memory uniformBytes = abi.encodePacked(b1);
            bytes32 prevBlock = b1;
            // compute b_i for i = 2 to ell
            for (uint256 i = 2; i <= ell; i++) {
                // strxor(b0, b_{i-1})
                bytes32 xorInput = b0 ^ prevBlock;
                bytes memory iBytes = I2OSP(i, 1);
                // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
                bytes32 bi = sha256(bytes.concat(xorInput, iBytes, dstPrime));

                // append b_i to uniform_bytes and update prev_block
                uniformBytes = abi.encodePacked(uniformBytes, bi);
                prevBlock = bi;
            }

            result = uniformBytes;
        }

        // return substr(uniform_bytes, 0, len_in_bytes)
        assembly {
            // note truncate to outputLen, leave dirty memory
            mstore(result, outputLen)
        }
    }

    /// @dev Convert nonnegative integer to its big-endian byte representation as per RFC8017::4.1
    /// https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    /// @param x Nonnegative integer to convert
    /// @param xLen Length for the output octet byte array
    /// @return _ The resulting octet byte array
    function I2OSP(uint256 x, uint256 xLen) public pure returns (bytes memory) {
        // enforce `x < 256 ** xLen`; if `xLen >= 32` then any `uint256 x` is valid
        if (xLen < 32 && x >= 256 ** xLen) {
            revert I2OSPIntegerTooLarge(x);
        }

        bytes memory octet = new bytes(xLen);
        for (uint256 i; i < xLen; i++) {
            // write in big-endian order
            octet[xLen - 1 - i] = bytes1(uint8(x >> (8 * i)));
        }

        return octet;
    }

    /// @dev Extract and process a single field element from uniform bytes
    /// @param uniformBytes The uniform random bytes from an `expand_message` schema (we use xmd)
    /// @param index The index of the field element to extract
    /// @return _ The processed field element
    function processFieldElement(bytes memory uniformBytes, uint256 index) public view returns (Fp memory) {
        // extract 64 bytes starting at `elm_offset = L * (j + i * m)` where `m = 1` and `j = 0`
        uint256 elmOffset = L * index;
        // `tv = substr(uniform_bytes, elm_offset, L)`
        bytes memory tv = extractBytes(uniformBytes, elmOffset, L);
        // reduce modulo p to ensure the result is a valid field element ie `e_j = OS2IP(tv) mod p`
        bytes memory ej = Math.modExp(tv, hex"01", P);
        // pad to 64 bytes with leading zeroes
        bytes memory data = new bytes(L);
        fieldElementToEIP2537Bytes(ej, 0, data, 0);

        return Fp(data);
    }

    /// @dev Extract a slice of bytes from a larger byte array
    /// @param source The source byte array
    /// @param offset Starting position in the source array
    /// @param length Number of bytes to extract
    /// @return _ The extracted bytes
    function extractBytes(bytes memory source, uint256 offset, uint256 length) public pure returns (bytes memory) {
        if (offset + length > source.length) revert LengthTooLarge(length);

        bytes memory result = new bytes(length);
        for (uint256 i; i < length; ++i) {
            result[i] = source[offset + i];
        }

        return result;
    }

    /// @dev Pads a 48-byte BLS12-381 field element to 64 bytes with 16 leading zeros for EIP2537
    /// @param source Source bytes containing the field element
    /// @param sourceOffset Offset in source where the 48-byte field element starts
    /// @param dest Destination bytes to write the padded element.
    /// @param destOffset Offset in dest where the 64-byte padded element should start,
    /// meaning the bytes in range `dest[destOffset:destOffset + 16]` must be zero!
    function fieldElementToEIP2537Bytes(
        bytes memory source,
        uint256 sourceOffset,
        bytes memory dest,
        uint256 destOffset
    )
        public
        pure
    {
        if (sourceOffset + FIELD_ELEMENT_SIZE > source.length) revert InvalidFpOffset();
        if (destOffset + EIP2537_FIELD_ELEMENT_SIZE > dest.length) revert InvalidFpOffset();

        for (uint256 i; i < FIELD_ELEMENT_SIZE; ++i) {
            dest[destOffset + 16 + i] = source[sourceOffset + i];
        }
    }

    /// @dev Extracts a 48-byte BLS12-381 field element from EIP2537 64-byte padded format
    /// @param paddedElement 64-byte EIP2537 padded field element (16 zeros + 48 bytes)
    /// @param paddedOffset The offset in the padded byte array to start reading
    /// @param dest The destination byte array to write the 48-byte element
    /// @param destOffset The offset in the destination to start writing
    function eip2537BytesToFieldElement(
        bytes memory paddedElement,
        uint256 paddedOffset,
        bytes memory dest,
        uint256 destOffset
    ) 
        public 
        pure 
    {
        if (paddedOffset + EIP2537_FIELD_ELEMENT_SIZE > paddedElement.length) {
            revert InvalidPoint(paddedElement.length, EIP2537_FIELD_ELEMENT_SIZE);
        }

        // Verify the first 16 bytes are zeros (required by EIP2537)
        for (uint256 i = 0; i < 16; i++) {
            if(paddedElement[paddedOffset + i] != 0) revert InvalidPadding();
        }

        // Extract bytes 16-63 (the actual field element)
        for (uint256 i = 0; i < FIELD_ELEMENT_SIZE; i++) {
            dest[destOffset + i] = paddedElement[paddedOffset + 16 + i];
        }
    }
}
