package it.zwets.sms.crock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

public class PhoneNumberEncoderTest {

	@Test
	public void testTooShort() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
        assertThrows(IllegalArgumentException.class, () -> pne.encode("0"));
	}

	@Test
	public void testTooLong() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
        assertThrows(IllegalArgumentException.class, () -> pne.encode("0000000000"));
	}

	@Test
	public void testNotCrock() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertThrows(IllegalArgumentException.class, () -> pne.decode("ABC+DEF"));
	}

	@Test
	public void testDashlessCrock() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		pne.decode("ABCDEF");
	}

	@Test
	public void testZero() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("000-000", pne.encode("000000000"));
	}

	@Test
	public void testDecodeZero() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("000000000", pne.decode("000-000"));
	}

	@Test
	public void testLow() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("000000001", pne.decode(pne.encode("000000001")));
	}

	@Test
	public void testRange() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		for (int n = 987654321; n > 0; n -= 12345678) {
			String number = String.format("%09d", n);
			assertEquals(number, pne.decode(pne.encode(number)));
		}
	}

	@Test
	public void testHigh() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("999999999", pne.decode(pne.encode("999999999")));
	}
	
	@Test
	public void testEncodeZwets() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("DBR-YT6", pne.encode("782334124"));
	}

	@Test
	public void testDecodeZwets() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("782334124", pne.decode("DBR-YT6"));
	}

	@Test
	public void testBlowUp() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertThrows(IllegalArgumentException.class, () -> pne.decode("RRR-RRR"));  // decodes to >999999999
	}
	
	@Test
	public void testLowerCase() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals(pne.decode("ABC-DEF"), pne.decode("abc-def"));
	}

	@Test
	public void testDisambiguation() {
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals(pne.decode("Lli-1Oo"), pne.decode("LLI-100"));
	}

	@Test
	public void testFacePalm() { // Crockford didn't want the U in it
		PhoneNumberEncoder pne = new PhoneNumberEncoder();
		assertEquals("FVC-K1T", pne.encode("182237814"));
	}
}