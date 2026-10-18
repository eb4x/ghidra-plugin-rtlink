package ebbex.rtlink;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

/**
 * Switch tables that live in DGROUP data, dispatched through {@code JMP word ptr [reg]}
 * and bounded by their own entries rather than by a guard.
 */
final class DataSwitchTables {

	/** {@code JMP word ptr [reg]} — opcode FF, reg field 4, for the DGROUP-table form. */
	private static final byte DATA_DISPATCH_OPCODE = (byte) 0xFF;
	private static final int DATA_DISPATCH_REG_OPCODE = 4;

	/** Instructions to look back over for the {@code ADD} and {@code MOV} that build the pointer. */
	private static final int POINTER_SCAN_LIMIT = 8;

	/**
	 * A DGROUP table is bounded by its entries rather than by a guard, so a single valid
	 * entry proves nothing — that is one plausible word, which data is full of. Two
	 * consecutive ones landing inside the dispatching function is already a strong signal.
	 */
	private static final int MIN_DATA_TABLE_ENTRIES = 2;

	private DataSwitchTables() {
	}

	/**
	 * Recover a switch table that lives in <b>DGROUP data</b> rather than after the code,
	 * dispatched through {@code JMP word ptr [reg]}:
	 * <pre>
	 *   MOV DI,0xb26a          ; table base — a DS offset, not a CS one
	 *   XOR CX,CX
	 *   MOV CL,[BX + SI + 5]   ; the index, straight out of a struct field
	 *   ADD DI,CX
	 *   JMP word ptr [DI]      ; ROE2MAIN.EXE 122e:5280
	 * </pre>
	 * Nothing bounds this table the way a {@code CMP} bounds the CS-relative form — the
	 * index is a byte read from memory, already scaled — so the entries themselves have to
	 * settle where the table ends: read words until one is not a plausible case target.
	 * <p>
	 * A case target lies inside the function that dispatches to it, and that is the bound
	 * used — see {@link CaseRange}. It is a sharp one here: ROE2MAIN's table is four
	 * entries ({@code 52ae, 5282, 528a, 52a3}, all within {@code FUN_122e_51d5}) followed
	 * immediately by unrelated variables whose first word, {@code 0x0078}, is a perfectly
	 * valid instruction address in the same block — inside a <em>different</em> function.
	 * Only the containing-function test rejects it; "is it code" does not.
	 * <p>
	 * Recovering it matters beyond the table: left alone, {@code DecompilerSwitchAnalyzer}
	 * tries to resolve the branch itself, fails to bound it, and explores — 117 seconds of
	 * analysis and a flood of p-code errors chasing garbage targets into unmapped memory,
	 * all from this one dispatch. Adding computed references is what makes it stand down.
	 */
	static List<Address> recover(Program program, Instruction dispatch, MemoryBlock block) {
		Register base = dataDispatchRegister(dispatch);
		if (base == null) {
			return null;
		}

		// Walk back for the two instructions that build the pointer: the index being added
		// in, and the constant table base it is added to. Any other write of the base
		// register in between means this is not the idiom.
		int tableOffset = -1;
		Instruction instruction = dispatch.getPrevious();
		boolean indexAdded = false;
		for (int i = 0; i < POINTER_SCAN_LIMIT && instruction != null; i++) {
			if (!block.contains(instruction.getMinAddress())) {
				return null;
			}
			if (!indexAdded) {
				if ("ADD".equals(instruction.getMnemonicString()) &&
					base.equals(instruction.getRegister(0)) &&
					instruction.getRegister(1) != null) {
					indexAdded = true;
				}
				else if (X86.changes(instruction, base)) {
					return null;
				}
			}
			else if ("MOV".equals(instruction.getMnemonicString()) &&
				base.equals(instruction.getRegister(0))) {
				Scalar table = instruction.getScalar(1);
				if (table == null) {
					return null;
				}
				tableOffset = (int) table.getUnsignedValue();
				break;
			}
			else if (X86.changes(instruction, base)) {
				return null;
			}
			instruction = instruction.getPrevious();
		}
		if (tableOffset < 0) {
			return null;
		}

		// The table is at DS:offset. DS is only set over code by RTLinkOverlayAnalyzer's
		// DGROUP pass, so a value here both names the segment and confirms the assumption
		// holds at this instruction.
		Register ds = program.getLanguage().getRegister("DS");
		if (ds == null) {
			return null;
		}
		RegisterValue dsValue =
			program.getProgramContext().getRegisterValue(ds, dispatch.getMinAddress());
		if (dsValue == null || !dsValue.hasValue()) {
			return null;
		}

		SegmentedAddressSpace space =
			(SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
		Address table = space.getAddress(dsValue.getUnsignedValue().intValue() & 0xffff,
			tableOffset);
		if (!program.getMemory().contains(table)) {
			return null;
		}

		AddressSetView range = CaseRange.of(program, dispatch, block);
		if (range == null) {
			Msg.debug(RTLinkSwitchTableAnalyzer.class,
				String.format("RTLink: data dispatch at %s reads a table at %s, but nothing calls "
					+ "into the code around it — cannot bound the table",
					dispatch.getMinAddress(), table));
			return null;
		}
		int segment = ((SegmentedAddress) block.getStart()).getSegment();

		Listing listing = program.getListing();
		Set<Address> destinations = new LinkedHashSet<>();
		try {
			for (int i = 0; i < CsDispatch.MAX_TABLE_ENTRIES; i++) {
				int offset = program.getMemory().getShort(table.add(2L * i)) & 0xffff;
				Address destination = space.getAddress(segment, offset);
				// The first entry that is not a case target of this function ends the
				// table — there is nothing else to say where it stops. "Case target"
				// cannot mean "already an instruction": these targets are reachable only
				// through the table, so nothing has disassembled them yet. It means
				// inside the dispatching function and not splitting an instruction that
				// is already there — the same test the overlay path makes.
				if (!range.contains(destination)) {
					break;
				}
				Instruction existing = listing.getInstructionContaining(destination);
				if (existing != null && !existing.getMinAddress().equals(destination)) {
					break;
				}
				destinations.add(destination);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// Unreadable memory after the last entry ends the table like any non-entry does;
			// the entries already read stand.
		}

		// One entry is not a switch; it is a coincidence.
		if (destinations.size() < MIN_DATA_TABLE_ENTRIES) {
			Msg.debug(RTLinkSwitchTableAnalyzer.class,
				String.format("RTLink: data dispatch at %s reads a table at %s that yields only "
					+ "%d target(s) in %s — not taken as a switch", dispatch.getMinAddress(),
					table, destinations.size(), range));
			return null;
		}
		return new ArrayList<>(destinations);
	}

	/**
	 * The base register of a {@code JMP word ptr [reg]} — a computed jump through memory
	 * with no segment override and no displacement — or null if {@code dispatch} is not one.
	 * A {@code CS:} override means the CS-relative form, which {@link CsDispatch}
	 * handles; a displacement means a single function pointer, not a table.
	 */
	private static Register dataDispatchRegister(Instruction dispatch) {
		if (!dispatch.getFlowType().isComputed() || !dispatch.getFlowType().isJump()) {
			return null;
		}
		byte[] bytes;
		try {
			bytes = dispatch.getBytes();
		}
		catch (MemoryAccessException e) {
			return null;
		}
		// FF /4 with mod=00 and no SIB/disp16: exactly [BX], [SI], [DI] or [BX+SI]-style.
		if (bytes.length != 2 || bytes[0] != DATA_DISPATCH_OPCODE) {
			return null;
		}
		int modrm = bytes[1] & 0xff;
		if ((modrm >> 6) != 0 || ((modrm >> 3) & 0x7) != DATA_DISPATCH_REG_OPCODE) {
			return null;
		}
		// The operand is memory, not a register, so getRegister() does not answer this —
		// the base register has to be picked out of the operand's objects.
		for (Object operand : dispatch.getOpObjects(0)) {
			if (operand instanceof Register register) {
				return register;
			}
		}
		return null;
	}
}
