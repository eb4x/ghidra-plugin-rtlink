package ebbex.rtlink;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;

/**
 * A {@code x86:LE:16:Real Mode} {@link ProgramBuilder} with the set-up steps the RTLink tests
 * share. Get one from {@link RealModeTest#realMode}, which disposes it after the test.
 * <p>
 * {@link #disassemble(String, int, boolean)} is the builder's own and runs auto-analysis
 * afterwards; {@link #decode} disassembles and nothing else, so a test sees only what its
 * own pass adds.
 */
final class RealMode extends ProgramBuilder {

	RealMode(String name) throws Exception {
		super(name, _X86_16_REAL_MODE);
	}

	/** An executable block named {@code CODE}. */
	MemoryBlock code(String start, int length) throws Exception {
		return code("CODE", start, length);
	}

	/** An executable block. */
	MemoryBlock code(String name, String start, int length) throws Exception {
		MemoryBlock block = createMemory(name, start, length);
		withTransaction(() -> block.setExecute(true));
		return block;
	}

	/** A block that is not executable. */
	MemoryBlock data(String name, String start, int length) {
		return createMemory(name, start, length);
	}

	/** Write {@code hex} (see {@link Hex#parse}) at {@code at}, without disassembling it. */
	void bytes(String at, String hex) throws Exception {
		setBytes(at, Hex.parse(hex));
	}

	/**
	 * Disassemble the {@code length} bytes at {@code at} as {@link #disassemble(String, int,
	 * boolean)} does, every undefined byte in the range a seed and flow kept inside it, but
	 * without running any analysis.
	 */
	void decode(String at, int length, boolean followFlow) {
		Address start = addr(at);
		AddressSet range = new AddressSet(start, start.add(length - 1));
		withTransaction(() -> Disassembler.getDisassembler(getProgram(), TaskMonitor.DUMMY, null)
				.disassemble(range, range, followFlow));
	}

	/** The disassembler's own error bookmark at {@code at}, as it leaves one for a conflict. */
	void errorMark(String at, String text) {
		withTransaction(() -> getProgram().getBookmarkManager()
				.setBookmark(addr(at), BookmarkType.ERROR, Disassembler.ERROR_BOOKMARK_CATEGORY,
					text));
	}

	/** The targets of the computed-jump references from {@code from}. */
	Set<Address> computedTargets(String from) {
		Set<Address> targets = new HashSet<>();
		for (Reference ref : getProgram().getReferenceManager().getReferencesFrom(addr(from))) {
			RefType type = ref.getReferenceType();
			if (type.isComputed() && type.isJump()) {
				targets.add(ref.getToAddress());
			}
		}
		return targets;
	}
}
