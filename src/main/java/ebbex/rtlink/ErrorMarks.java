package ebbex.rtlink;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

/** Where the disassembler's ERROR marks for a stretch of junk lie. */
final class ErrorMarks {

	private ErrorMarks() {
	}

	/**
	 * The junk's addresses plus the byte after it: a run the disassembler abandoned leaves its
	 * ERROR mark one past the last instruction it managed to decode, so the mark lies just
	 * outside the junk itself. Only a bookmark sweep may reach that byte — clearing it would
	 * take the next real instruction with it.
	 */
	static AddressSetView markedRange(AddressSetView junk) {
		AddressSet marked = new AddressSet(junk);
		Address after = junk.getMaxAddress().next();
		if (after != null) {
			marked.add(after, after);
		}
		return marked;
	}
}
