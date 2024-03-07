package it.zwets.sms.crock;

import java.util.function.LongFunction;

/**
 * Utility class to encode phone numbers to secure crock codes.
 * 
 * This class converts between 9-digit phone numbers and 6-letter "crock codes".
 * For instance, "123456789" might be encoded as Q2P-AB9.
 * 
 * The encoding uses the Crockford Base32 alphabet (including decoding of small
 * caps and ambiguous characters), but adds encryption so that phone numbers
 * cannot be easily recovered from crock codes.
 *
 * This encryption is intended to keep phone numbers confidential, not highly
 * secure.  A person with the intention to decrypt can do so by using this code,
 * albeit with considerable effort if you use your own shuffle key.
 *
 * The current implementation works for 9-digit phone numbers only.  These can
 * be encoded in 30 bits, and thus in 6 Crockford characters (6 x 5 bits).
 * 
 * If you need to accommodate larger phone numbers, you'll have to adapt the code.
 * If your numbers are smaller, use zero-padding, or better use random padding.
 * 
 * @author zwets
 */
public class PhoneNumberEncoder {

	/* Default shuffle, used if you do not set your own. 
	 * Note we deliberately code 0 as "0", so that 000-000 is 000000000,
	 * which may be convenient for missing data. */
	private static final int[] DEFAULT_SHUFFLE = {
			0, 2, 9, 7, 28, 12, 30, 25, 13, 6, 10, 15, 19, 23, 14, 18,
			5, 21, 3, 11, 26, 4, 16, 8, 22, 29, 20, 17, 31, 1, 27, 24 };

	/* Default encoder, used if you do not set your own */
	private CrockEncoder crockEncoder;

	/**
	 * Construct an encoder that uses the default bit mixer and shuffle.
	 */
	public PhoneNumberEncoder() {
		this(DEFAULT_SHUFFLE);
	}

	/**
	 * Construct an encoder with a custom shuffled alphabet.
	 * 
	 * @param shuffle array specifying the shuffled order of the alphabet
	 * @see #PhoneNumberEncoder(LongFunction, LongFunction, int[])
	 */
	public PhoneNumberEncoder(int[] shuffle) {
		this(PhoneNumberEncoder::mixBits, PhoneNumberEncoder::unmixBits, shuffle);
	}

	/**
	 * Construct an encoder with a custom bit mixer and shuffled alphabet.
	 * 
	 * @param mixer function to mix the input bits
	 * @param unmixer function to demix the bits on decode
	 * @param shuffle array specifying the shuffled order of the alphabet
	 * @see CrockEncoder#CrockEncoder(LongFunction, LongFunction, int[])
	 */
	public PhoneNumberEncoder(LongFunction<Long> mixer, LongFunction<Long> unmixer, int[] shuffle) {
		this.crockEncoder = new CrockEncoder(mixer, unmixer, shuffle);
	}

	/**
	 * Returns the shuffled alphabet used by this encoder.
	 * @return the shuffled Crock Code alphabet used
	 */
	public String getAlphabet() {
	    return this.crockEncoder.getAlphabet();
	}
	
	/**
	 * Encode phoneNumber to its crock code
	 * 
	 * The phone number must be a 9-digit string, or IllegalArgumentException will be thrown.
	 * 
	 * @param phoneNumber a 9-digit string
	 * @return a 6-digit crock code formatted with a dash in the middle"
	 */
	public String encode(String phoneNumber) {
		
		if (!phoneNumber.matches("^[0-9]{9}$")) {
			throw new IllegalArgumentException("Not a 9-digit phone number: %s".formatted(phoneNumber));
		}
		
		String code = crockEncoder.encode(Long.parseLong(phoneNumber), 6);

		return code.substring(0, 3) + "-" + code.substring(3, 6);
	}

	/**
	 * Decode crockCode to its phone number
	 * @param crockCode the 6 digit crock code, with optional dash(es)
	 * @return the 9 digit phone number
	 */
	public String decode(String crockCode) {

		if (!crockCode.matches("^[A-Za-z0-9]{3}-?[A-Za-z0-9]{3}$")) {
			throw new IllegalArgumentException("Not a valid crock code: %s".formatted(crockCode));
		}
		
		long value = crockEncoder.decode(crockCode);
		
		if (value < 0L || value > 999999999L) {
			throw new IllegalArgumentException("Crock code doesn't decode to a valid phone number: %s".formatted(crockCode));
		}

		return String.format("%09d",value);
	}

	/* Default bit mixer function.  Makes sure that the bits of each input nyckle
	   end up spread across all output nyckles. */
	private static long mixBits(long n) {
		// We mix the 30 bits, which would be encoded as 6 groups of 5 bits, by
		// 'going down the columns', thus creating each target nyckle by taking
		// a bit from five different input nyckles.
		// So, starting at the low end, bits 0, 1, 2, ... go to 29, 23, 17, ...
		long r = 0;
		for (int i = 0; i < 6; ++i)
			for (int j = 0; j < 5; ++j, n >>= 1)
				r |= (n & 1) << (29 - (6*j + i));
		return r;
	}

	/* Default bit unmixer, undoes the default bit mixer. */	
	private static long unmixBits(long n) {
		// The inverse of mixBits; we transpose back the 5 by 6 to 6 by 5.
		// So, we successively see bits for: 29, 24, 19, 14, 9, 4; 28, 23, ....
		long r = 0;
		for (int i = 0; i < 5; ++i)
			for (int j = 0; j < 6; ++j, n >>= 1)
				r |= (n & 1) << (29 - (5*j + i));
		return r;
	}
}
