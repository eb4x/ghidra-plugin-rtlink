package ebbex.rtlink;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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
		Register base = dataDispatchRegister(program, dispatch);
		if (base == null) {
			return null;
		}

		// Walk back for the two instructions that build the pointer: the index being added
		// in, and the constant table base it is added to. Any other write of the base
		// register in between means this is not the idiom.
		int tableOffset = -1;
		Instruction instruction = X86.previousInBlock(dispatch, block);
		boolean indexAdded = false;
		for (int i = 0; i < POINTER_SCAN_LIMIT && instruction != null; i++) {
			if (!indexAdded) {
				X86.RegisterPair add = X86.registerPair(program, instruction, X86.ADD * 8);
				if (add != null && base.equals(add.destination())) {
					indexAdded = true;
				}
				else if (X86.changes(instruction, base)) {
					return null;
				}
			}
			else if ("MOV".equals(instruction.getMnemonicString()) &&
				base.equals(X86.movDestination(instruction))) {
				Long table = X86.movImmediate(instruction);
				if (table == null) {
					return null;
				}
				tableOffset = table.intValue();
				break;
			}
			else if (X86.changes(instruction, base)) {
				return null;
			}
			instruction = X86.previousInBlock(instruction, block);
		}
		if (tableOffset < 0) {
			return null;
		}

		// The table is at DS:offset.
		Integer ds = X86.dataSegment(program, dispatch.getMinAddress());
		if (ds == null) {
			return null;
		}

		SegmentedAddressSpace space = X86.space(program);
		Address table = space.getAddress(ds, tableOffset);
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
		int segment = X86.segment(block);
		if (segment < 0) {
			return null;
		}

		// The first entry that is not a case target of this function ends the table — there
		// is nothing else to say where it stops. "Case target" cannot mean "already an
		// instruction": these targets are reachable only through the table, so nothing has
		// disassembled them yet. It means inside the dispatching function and not splitting
		// an instruction that is already there — the test every table form makes.
		List<Address> destinations =
			CaseTable.readWhile(program, table, CsDispatch.MAX_TABLE_ENTRIES, offset -> {
				Address destination = space.getAddress(segment, offset);
				return range.contains(destination) ? destination : null;
			});

		// One entry is not a switch; it is a coincidence.
		if (destinations.size() < MIN_DATA_TABLE_ENTRIES) {
			Msg.debug(RTLinkSwitchTableAnalyzer.class,
				String.format("RTLink: data dispatch at %s reads a table at %s that yields only "
					+ "%d target(s) in %s — not taken as a switch", dispatch.getMinAddress(),
					table, destinations.size(), range));
			return null;
		}
		return destinations;
	}

	/**
	 * The base register of a {@code JMP word ptr [reg]} — a computed jump through memory
	 * with no segment override and no displacement — or null if {@code dispatch} is not one.
	 * A {@code CS:} override means the CS-relative form, which {@link CsDispatch}
	 * handles; a displacement means a single function pointer, not a table.
	 */
	private static Register dataDispatchRegister(Program program, Instruction dispatch) {
		if (!dispatch.getFlowType().isComputed() || !dispatch.getFlowType().isJump()) {
			return null;
		}
		byte[] bytes = X86.bytes(dispatch);
		// FF /4 with mod=00 and no SIB/disp16: exactly [BX], [SI], [DI] or [BX+SI]-style.
		if (bytes.length != 2 || bytes[0] != DATA_DISPATCH_OPCODE) {
			return null;
		}
		X86.ModRm modrm = X86.modRm(bytes, 1);
		if (modrm.mod() != 0 || modrm.reg() != DATA_DISPATCH_REG_OPCODE) {
			return null;
		}
		// A single base register: rm 4 = [SI], 5 = [DI], 7 = [BX]. The two-register forms
		// ([BX+SI] and the like) are not a table pointer built in one register.
		return switch (modrm.rm()) {
			case 4 -> X86.register(program, 6, 2);
			case 5 -> X86.register(program, 7, 2);
			case 7 -> X86.register(program, 3, 2);
			default -> null;
		};
	}
}
