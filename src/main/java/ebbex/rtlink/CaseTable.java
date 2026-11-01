package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.IntFunction;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * The words of a switch jump table and the case targets they name, read the same way for
 * every table form. An entry is a case target only if its form resolves it ({@code target}
 * returns null otherwise), it does not land inside the table's own bytes, and it does not
 * split an instruction already decoded: either would mean the guard was misread or the table
 * anchored to the wrong base. The table never runs past the end of its 64KB segment.
 */
final class CaseTable {

	private CaseTable() {
	}

	/**
	 * The targets of exactly {@code entries} words at {@code table}, in table order without
	 * repeats, or null if any entry is not a case target or cannot be read: a counted table
	 * is all or nothing.
	 */
	static List<Address> readAll(Program program, Address table, int entries,
			IntFunction<Address> target) {
		if (entries > wordsLeftInSegment(table)) {
			return null;
		}
		Set<Address> destinations = new LinkedHashSet<>();
		long tableEnd = table.getOffset() + 2L * entries;
		try {
			for (int i = 0; i < entries; i++) {
				Address destination = caseTarget(program, table, i, tableEnd, target);
				if (destination == null) {
					return null;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException _) {
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The targets of the words at {@code table} up to the first that is not a case target or
	 * cannot be read, at most {@code maxEntries}: for a table nothing counts, which ends where
	 * its entries stop making sense.
	 */
	static List<Address> readWhile(Program program, Address table, int maxEntries,
			IntFunction<Address> target) {
		int limit = Math.min(maxEntries, wordsLeftInSegment(table));
		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < limit; i++) {
				long tableEnd = table.getOffset() + 2L * (i + 1);
				Address destination = caseTarget(program, table, i, tableEnd, target);
				if (destination == null) {
					break;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException _) {
			// Unreadable memory after the last entry ends the table like any non-entry does.
		}
		return new ArrayList<>(destinations);
	}

	/** Entry {@code i}'s target, or null if it is not one; {@code tableEnd} is a flat offset. */
	private static Address caseTarget(Program program, Address table, int i, long tableEnd,
			IntFunction<Address> target) throws MemoryAccessException {
		int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
		Address destination = target.apply(offset);
		if (destination == null) {
			return null;
		}
		if (destination.getAddressSpace().equals(table.getAddressSpace()) &&
			destination.getOffset() >= table.getOffset() && destination.getOffset() < tableEnd) {
			return null; // a case target inside its own table
		}
		Instruction existing = program.getListing().getInstructionContaining(destination);
		if (existing != null && !existing.getMinAddress().equals(destination)) {
			return null; // splits an instruction already there
		}
		return destination;
	}

	/** How many words fit between {@code table} and the end of its 64KB segment. */
	private static int wordsLeftInSegment(Address table) {
		if (!(table instanceof SegmentedAddress at)) {
			return Integer.MAX_VALUE; // an overlay: its block bounds the table
		}
		return (0x10000 - at.getSegmentOffset()) / 2;
	}
}
