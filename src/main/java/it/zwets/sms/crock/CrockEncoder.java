package it.zwets.sms.crock;

import java.util.function.LongFunction;

/**
 * Implements a Crockford Base32 encoder with optional encryption.
 *
 * Use {@link #encode(long)} to convert a long to a Base32 Crockford
 * string (a <i>crock code</i>), and {@link #decode(String)} to convert
 * back from crock code to long.
 * 
 * The class offers two levels of encryption: shuffling the letters in
 * the encoding alphabet, and mixing the bits in the input value.
 * 
 * The effect of shuffling is that successive inputs do not encode as
 * successive outputs. Clearly, this is relatively easy to crack, and
 * inputs that are close together still generate similar crock codes.
 * 
 * Adding proper bit mixing, in particular swapping bits between the
 * 5-bit nyckles, will create codes with no easily decodable relation
 * to their numeric value.
 */
public class CrockEncoder {

	/* Original Crockford base32 nyckle to character mapping. */
	private static final char[] CROCKFORD_CODES = {
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
			'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z' };

	/* Unmangled indices. */
	private static final int[] NO_MANGLE = {
			 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,  };
	
	/* Map of nyckle to encrypted nyckle. */
	private int[] mangle;

	/* Map of encrypted nyckle to nyckle. */
	private int[] unmangle;
	
	/* User function to mix the bits in the long. */
	private LongFunction<Long> bitMixer;
	
	/* User function to undo the bit mixing. */
	private LongFunction<Long> unMixer;

	/** 
	 * Create a standard, non-encrypting Crockford Base32 Encoder.
	 * 
	 * @see #CrockEncoder(boolean)
	 */
	public CrockEncoder() {
		this(null);
	}
	
	/**
	 * Create an CrockEncoder with a non-standard alphabet order
	 * 
	 * Parameter mangleTable must be an array of the numbers [0..31] in
	 * an order of your choosing.  Values mangleTable[i] give the indices
	 * into the crockford alphabet of the nyckles with value i.
	 * 
	 * Use {@link #CrockEncoder(LongFunction, LongFunction, int[])}
	 * for more advanced encryption.
	 * 
	 * @param mangleTable an randomised array of the set [0..31]
	 * @see  for details
	 */
	public CrockEncoder(int[] mangleTable) {
		this(x -> x, x -> x, mangleTable);
	}

	/**
	 * Create an encrypting CrockEncoder.
	 * 
	 * This creates a CrockEncoder that mixes the bits in the input
	 * before encoding it, optionally with a non-standard alphabet.
	 * 
	 * The bitMixer function must take a long and return the encrypted
	 * value of that long (clearly this function must be bijective, or
	 * you won't have unique crock codes).  The provided unmixer must 
	 * be the inverse of that operation.
	 * 
	 * See the {@link PhoneNumberEncoder} for an example of a bit mixer.
	 * 
	 * A mangleTable can be passed in to shuffle the alphabet to a
	 * non-standard order (see {@link #CrockEncoder(int[])}).  If null,
	 * then the default Crockford order is used.
	 * 
	 * @param bitMixer the encoding (bit mixing) function 
	 * @param unMixer the decoding (bit unmixing) function
	 * @param mangleTable the mangle table to use, null for no mangling
	 */
	public CrockEncoder(LongFunction<Long> bitMixer, LongFunction<Long> unMixer, int[] mangleTable) {
		this.bitMixer= bitMixer;
		this.unMixer= unMixer;
		setMangle(mangleTable == null ? NO_MANGLE : mangleTable);
	}

	/**
	 * Encode long value to crock code.
	 * 
	 * The crock code returned is not "zero-padded" to the left.
	 * See {@link #encode(long, int)} to perform padding.
	 * 
	 * @param value the value to encode
	 * @return the crock code
	 */
	public String encode(long value) {
		return encode(value, 0);
	}

	/**
	 * Encode long value to crock code with given minimum width
	 * 
	 * @param value the value to encode
	 * @width the minimum width of the generated string
	 * @return the crock code
	 */
	public String encode(long value, int width) {
		StringBuilder b = new StringBuilder();
		
		long n = bitMixer.apply(value);
		do {
			b.insert(0, CROCKFORD_CODES[mangle[(int)(n & 31)]]);
			n >>= 5;
		} while (--width > 0 || n != 0L);
		
		return b.toString();
	}
	
	/**
	 * Decode crock code to its long value
	 * 
	 * The crock code may contain dashes (which will be ignored), but all
	 * other invalid characters will yield an IllegalArgumentException.
	 * 
	 * If the crock code is too long to fit in a long, then the output is
	 * undefined.
	 * 
	 * @param crock the crock code to decode
	 * @return the long value
	 */
	public long decode(String crock) {
		return unMixer.apply(crock.chars()
				.filter(c -> c != '-')
				.mapToLong(c -> unmangle[charIndex((char)c)])
				.reduce(0L, (r,x) -> (r << 5) | x));
	}

	private int charIndex(char c) {
		switch (c) {
		case '0': case 'O': case 'o': return 0;
		case '1': case 'I': case 'i': case 'L': case 'l': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A': case 'a': return 10;
		case 'B': case 'b': return 11;
		case 'C': case 'c': return 12;
		case 'D': case 'd': return 13;
		case 'E': case 'e': return 14;
		case 'F': case 'f': return 15;
		case 'G': case 'g': return 16;
		case 'H': case 'h': return 17;
		case 'J': case 'j': return 18;
		case 'K': case 'k': return 19;
		case 'M': case 'm': return 20;
		case 'N': case 'n': return 21;
		case 'P': case 'p': return 22;
		case 'Q': case 'q': return 23;
		case 'R': case 'r': return 24;
		case 'S': case 's': return 25;
		case 'T': case 't': return 26;
		case 'U': case 'u': case 'V': case 'v': return 27;
		case 'W': case 'w': return 28;
		case 'X': case 'x': return 29;
		case 'Y': case 'y': return 30;
		case 'Z': case 'z': return 31;
		default:
			throw new IllegalArgumentException("Invalid character in Base32 Crockford string: '" + c + "'");
		}
	}

	private void setMangle(int[] mangle) {
		this.mangle = validateMangle(mangle);
		this.unmangle = new int[32];
		for (int i = 0; i < 32; ++i) {
			this.unmangle[mangle[i]] = i;
		}
	}
	
	private int[] validateMangle(int[] mangle) {
		int[] checks = new int[32];
		assert mangle != null && mangle.length == 32;
		for (int i = 0; i < 32; ++i) {
			assert 0 <= mangle[i] && mangle[i] < 32;
			checks[mangle[i]] = 1;
		}
		for (int i = 0; i < 32; ++i) {
			assert checks[i] == 1;
		}
		return mangle;
	}
}
