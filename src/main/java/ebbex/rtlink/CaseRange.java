package ebbex.rtlink;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;

/**
 * Where the case targets of a dispatch may lie: the function that contains it, bounded
 * by call targets because the function may not exist yet.
 */
final class CaseRange {

	private CaseRange() {
	}

	/**
	 * The address range of the function containing {@code dispatch} — the region its case
	 * targets must lie in — or null when it cannot be established.
	 * <p>
	 * Bounded by <b>call targets</b>, not by the {@link FunctionManager} and not by a
	 * {@link Function#getBody() body}, because neither is usable here:
	 * <ul>
	 * <li>The body is derived by following flow, and the case targets of an unresolved
	 * computed jump are reachable only <em>through</em> the table — they are precisely the
	 * addresses the body leaves out. Bounding by it asks the switch to be resolved before
	 * it can be resolved.
	 * <li>The functions themselves may not exist yet. {@code FunctionAnalyzer} ("Create
	 * Function") sits at the same {@code CODE_ANALYSIS.before()} priority as
	 * {@link RTLinkSwitchTableAnalyzer}, and equal priorities run first-queued-first, so
	 * whether the dispatching function has been created when we look is not ours to decide.
	 * In ROE2MAIN.EXE it has not been: {@code FUN_122e_51d5} does not exist when
	 * {@code 122e:5280} is examined.
	 * </ul>
	 * What does exist by then is the disassembler's own call references. A function begins
	 * where something calls it, which is what {@code FunctionAnalyzer} keys on too, so the
	 * nearest call target at or below the dispatch starts the range and the nearest one
	 * above it ends the range — the same answer, one pass earlier.
	 */
	static AddressSetView of(Program program, Instruction dispatch, MemoryBlock block) {
		Address at = dispatch.getMinAddress();
		Address start = nearestCallTarget(program, block, at, false);
		if (start == null) {
			return null;
		}
		Address after = at.next();
		Address above =
			after == null ? null : nearestCallTarget(program, block, after, true);
		Address end = above == null ? block.getEnd() : above.subtract(1);
		return start.compareTo(end) > 0 ? null : new AddressSet(start, end);
	}

	/**
	 * The nearest address in {@code block} that something calls, searching from {@code from}
	 * (inclusive) in the given direction, or null if the block runs out first.
	 */
	private static Address nearestCallTarget(Program program, MemoryBlock block, Address from,
			boolean forward) {
		AddressIterator targets =
			program.getReferenceManager().getReferenceDestinationIterator(from, forward);
		while (targets.hasNext()) {
			Address target = targets.next();
			if (!block.contains(target)) {
				return null; // left the block: no call target this side of it
			}
			if (CodeEvidence.hasReferenceTo(program, target, RefType::isCall)) {
				return target;
			}
		}
		return null;
	}
}
