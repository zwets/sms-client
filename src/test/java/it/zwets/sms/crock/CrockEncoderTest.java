package it.zwets.sms.crock;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.function.LongFunction;

import org.junit.jupiter.api.Test;

public class CrockEncoderTest {

	@Test
	public void testSimple() {
		CrockEncoder coder = new CrockEncoder();
		assertEquals("0", coder.encode(0));
	}

	@Test
	public void testPlain() {
		CrockEncoder coder = new CrockEncoder();
		for (int i = 0; i < 128; ++i) {
			assertEquals(i, coder.decode(coder.encode(i)));
		}
	}

	@Test
	public void testHigh() {
		CrockEncoder coder = new CrockEncoder();
		for (int i = 999999000; i < 1000000000; ++i) {
			assertEquals(i, coder.decode(coder.encode(i)));
		}
	}

	final int[] myMangle = { 
			13, 6, 10, 15, 19, 23, 14, 18, 5, 21, 3, 11, 26, 4, 16, 8,
			22, 29, 20, 17, 31, 1, 27, 24, 25, 2, 9, 7, 28, 12, 30, 0 };

	@Test
	public void testMangle() {
		CrockEncoder coder = new CrockEncoder(myMangle);
		for (int i = 0; i < 128; ++i) {
			assertEquals(i, coder.decode(coder.encode(i)));
		}
	}
	
	private LongFunction<Long> xorMixer = n -> n ^ 0x3FFFFFFF;

	@Test
	public void testMixerEncode() {
		CrockEncoder coder = new CrockEncoder(xorMixer, xorMixer, null);
		assertEquals("ZZZZZZ", coder.encode(0));
	}
	
	@Test
	public void testMixerDecode() {
		CrockEncoder coder = new CrockEncoder(xorMixer, xorMixer, null);
		assertEquals(0L, coder.decode("ZZZZZZ"));
	}
	
	@Test
	public void testEncodeField() {
		CrockEncoder coder = new CrockEncoder();
		assertEquals("00", coder.encode(0, 2));
	}

	@Test
	public void testEncodeFieldOverflow() {
		CrockEncoder coder = new CrockEncoder(xorMixer, xorMixer, null);
		assertEquals("ZZZZZZ", coder.encode(0));
	}

	@Test
	public void testEncodeFieldUnderflow() {
		CrockEncoder coder = new CrockEncoder(xorMixer, xorMixer, null);
		assertEquals("0ZZZZZZ", coder.encode(0, 7));
	}
	
	@Test
	public void testMixing() {
		CrockEncoder coder = new CrockEncoder(xorMixer, xorMixer, null);
		for (int i = 0; i < 1000; ++i) {
			assertEquals(i, coder.decode(coder.encode(i)));
		}
	}
	
}
