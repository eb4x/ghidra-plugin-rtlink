package ebbex.rtlink;

import java.util.HexFormat;

/** Test bytes written as hex: pairs separated by any whitespace, {@code ;} to end of line is a comment. */
final class Hex {

	private Hex() {
	}

	/**
	 * The bytes of {@code text}, which may be a text block laid out like a listing:
	 * <pre>
	 *   55        ; PUSH BP
	 *   8b ec     ; MOV BP,SP
	 * </pre>
	 */
	static byte[] parse(String text) {
		var digits = new StringBuilder();
		for (String line : text.split("\n")) {
			int comment = line.indexOf(';');
			digits.append((comment < 0 ? line : line.substring(0, comment)).replaceAll("\\s", ""));
		}
		return HexFormat.of().parseHex(digits);
	}
}
