package ebbex.rtlink;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Code reached only through a far pointer the program builds to itself: {@code CS:imm}.
 * <p>
 * A routine that nothing calls or jumps to can still be the target of a far pointer
 * assembled from {@code CS} and a constant, which is how DOS code installs handlers and
 * return vectors. Three shapes, each on a straight-line run of at most {@value #WINDOW}
 * instructions:
 * <ul>
 * <li><b>A pointer stored into adjacent words</b>: the constant into {@code [m]} and CS into
 * {@code [m+2]}, by {@code MOV} or {@code XCHG}, directly or through registers. VICEROY's
 * INT 21h hook ({@code MOV ES:[0x84],0x574 ; MOV AX,CS ; MOV ES:[0x86],AX} at
 * {@code 210d:1b20}), its PSP terminate hook ({@code MOV ES:[0xa],0x7e3 ; MOV ES:[0xc],CS} at
 * {@code 275d:0732}) and the VM's return vector ({@code MOV AX,0x1554 ; MOV DX,CS ;
 * XCHG SS:[SI],AX ; XCHG SS:[SI+2],DX} at {@code 210d:29cd}).</li>
 * <li><b>A {@code DS:DX} pair handed to a routine that stores it</b> as such a pointer, with
 * {@code DS = CS}: RTLink's {@code $$RTL_REGISTER} handlers ({@code MOV AX,CS ; MOV DS,AX ;
 * MOV DX,0x701 ; CALLF $$RTL_REGISTER} at {@code 210d:0be3}).</li>
 * <li><b>DOS set-vector</b>, {@code INT 21h} with {@code AH = 25h}, {@code DS = CS} and a
 * constant {@code DX}.</li>
 * </ul>
 * Each target is referenced from the instruction that completes the pointer, disassembled,
 * and made a function: it is an entry by construction. Registers are tracked only as "holds
 * CS" or "holds this constant"; the state is dropped at every jump target and wherever the
 * flow does not fall through, and a call keeps only a {@code DS} its callee never writes.
 */
final class FarCodePointers {

	/** Longest straight-line run tracked from one reset. */
	private static final int WINDOW = 12;

	private static final int ES = 8;
	private static final int CS = 9;
	private static final int SS = 10;
	private static final int DS = 11;
	private static final String[] REGISTER_NAMES =
		{ "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "ES", "CS", "SS", "DS" };
	private static final int AX = 0;
	private static final int DX = 2;
	private static final int DIRECT = -1;

	/** A tracked value: CS itself, or a 16-bit constant. */
	private sealed interface Value permits HoldsCs, Constant {
	}

	private record HoldsCs() implements Value {
	}

	private record Constant(int value) implements Value {
	}

	private static final Value CS_VALUE = new HoldsCs();

	/** A memory word: segment (override or implied), base register (or direct), displacement. */
	private record Slot(int segment, int base, int disp) {
		Slot next() {
			return new Slot(segment, base, disp + 2);
		}

		Slot previous() {
			return new Slot(segment, base, disp - 2);
		}
	}

	private FarCodePointers() {
	}

	/** Find, reference, disassemble and make functions of every such target; returns the count. */
	static int recover(Program program, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Register[] registers = new Register[REGISTER_NAMES.length];
		for (int i = 0; i < registers.length; i++) {
			registers[i] = program.getLanguage().getRegister(REGISTER_NAMES[i]);
			if (registers[i] == null) {
				return 0; // not x86
			}
		}
		Map<Address, Instruction> targets = new LinkedHashMap<>();
		Map<Address, Boolean> pairStorers = new HashMap<>();
		Map<Address, Boolean> dsWriters = new HashMap<>();

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			monitor.checkCancelled();
			if (!block.isExecute() || !block.isInitialized() ||
				!(block.getStart() instanceof SegmentedAddress)) {
				continue;
			}
			Scan scan = new Scan(program, registers, pairStorers, dsWriters, targets);
			Instruction previous = null;
			for (Instruction instruction : listing.getInstructions(
				new AddressSet(block.getStart(), block.getEnd()), true)) {
				monitor.checkCancelled();
				if (previous == null ||
					!instruction.getMinAddress().equals(previous.getFallThrough()) ||
					CodeEvidence.hasReferenceTo(program, instruction.getMinAddress(),
						RefType::isJump)) {
					scan.reset();
				}
				scan.step(instruction);
				previous = instruction;
			}
		}

		int recovered = 0;
		for (Map.Entry<Address, Instruction> entry : targets.entrySet()) {
			monitor.checkCancelled();
			if (claim(program, entry.getValue(), entry.getKey(), monitor)) {
				recovered++;
			}
		}
		return recovered;
	}

	/** Reference, disassemble and make a function at {@code target}; true if anything was new. */
	private static boolean claim(Program program, Instruction source, Address target,
			TaskMonitor monitor) {
		boolean changed = false;
		if (!CodeEvidence.refersTo(source, target, _ -> true)) {
			program.getReferenceManager().addMemoryReference(source.getMinAddress(), target,
				RefType.DATA, SourceType.ANALYSIS, Reference.MNEMONIC);
		}
		Listing listing = program.getListing();
		if (listing.getInstructionAt(target) == null) {
			if (listing.getInstructionContaining(target) != null ||
				listing.getDefinedDataContaining(target) != null) {
				return false; // the bytes are already something else: no claim on them
			}
			if (usedAsData(program, target, source.getMinAddress())) {
				return false; // a far pointer to CS-resident data: an EXEC block, a buffer
			}
			new DisassembleCommand(target, null, true).applyTo(program, monitor);
			if (listing.getInstructionAt(target) == null) {
				return false;
			}
			changed = true;
		}
		if (program.getFunctionManager().getFunctionContaining(target) == null) {
			changed |= new CreateFunctionCmd(target).applyTo(program, monitor);
		}
		return changed;
	}

	/**
	 * True if anything but the pointer itself reads, writes or points at {@code target} as
	 * data. The same {@code CS:imm} pair builds a far pointer to a buffer or an EXEC parameter
	 * block as to a handler, and the bytes of such data are what the program's own loads and
	 * stores reference; a handler's entry is only ever jumped or called to.
	 */
	private static boolean usedAsData(Program program, Address target, Address pointer) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(target)) {
			RefType type = reference.getReferenceType();
			if (!reference.getFromAddress().equals(pointer) &&
				(type.isRead() || type.isWrite() || type.isData())) {
				return true;
			}
		}
		return false;
	}

	/** The register-and-slot state over one straight-line run. */
	private static final class Scan {
		private final Program program;
		private final Register[] registers;
		private final Map<Address, Boolean> pairStorers;
		private final Map<Address, Boolean> dsWriters;
		private final Map<Address, Instruction> targets;
		private final Value[] values = new Value[REGISTER_NAMES.length];
		private final Map<Slot, Value> slots = new HashMap<>();
		private final Deque<Value> stack = new ArrayDeque<>();
		private int steps;

		Scan(Program program, Register[] registers, Map<Address, Boolean> pairStorers,
				Map<Address, Boolean> dsWriters, Map<Address, Instruction> targets) {
			this.program = program;
			this.registers = registers;
			this.pairStorers = pairStorers;
			this.dsWriters = dsWriters;
			this.targets = targets;
			reset();
		}

		void reset() {
			java.util.Arrays.fill(values, null);
			values[CS] = CS_VALUE;
			slots.clear();
			stack.clear();
			steps = 0;
		}

		void step(Instruction instruction) {
			if (++steps > WINDOW) {
				reset();
				steps = 1;
			}
			byte[] bytes = X86.bytes(instruction);
			int i = X86.opcodeIndex(bytes);
			if (i < 0) {
				reset();
				return;
			}
			int segment = X86.segmentOverride(bytes);
			int op = bytes[i] & 0xff;
			if (!apply(instruction, bytes, i, op, segment)) {
				invalidateWrites(instruction);
				if (storesToMemory(instruction)) {
					slots.clear(); // STOSW, a byte MOV, ADD [m],..: a tracked word may be gone
				}
			}
			forgetSlotsAddressedThrough(instruction);
			if (!instruction.getFlowType().hasFallthrough()) {
				reset();
			}
		}

		/**
		 * A slot is keyed by its addressing mode, not by an address, so once {@code BX},
		 * {@code BP}, {@code SI} or {@code DI} changes, the slots addressed through it name
		 * other words: {@code MOV [DI],imm ; ADD DI,4 ; MOV [DI+2],CS} is not a pointer.
		 */
		private void forgetSlotsAddressedThrough(Instruction instruction) {
			for (Object result : instruction.getResultObjects()) {
				if (!(result instanceof Register written)) {
					continue;
				}
				for (int reg : ADDRESS_REGISTERS) {
					if (X86.overlaps(written, registers[reg])) {
						slots.keySet().removeIf(slot -> addressesThrough(slot, reg));
					}
				}
			}
		}

		private static boolean storesToMemory(Instruction instruction) {
			for (PcodeOp op : instruction.getPcode()) {
				if (op.getOpcode() == PcodeOp.STORE) {
					return true;
				}
			}
			return false;
		}

		/** Model the instructions that move CS or constants; false for anything else. */
		private boolean apply(Instruction instruction, byte[] b, int i, int op, int segment) {
			if (op >= 0xb8 && op <= 0xbf && i + 2 < b.length) { // MOV r16,imm16
				values[op - 0xb8] = new Constant(X86.word(b, i + 1));
				return true;
			}
			switch (op) {
				case 0x8c -> { // MOV r/m16,sreg
					int modrm = b[i + 1] & 0xff;
					Value value = segmentValue((modrm >> 3) & 3);
					if (modrm >> 6 == 3) {
						values[modrm & 7] = value;
					}
					else {
						store(instruction, slot(b, i + 1, segment), value);
					}
					return true;
				}
				case 0x8e -> { // MOV sreg,r/m16
					int modrm = b[i + 1] & 0xff;
					int sreg = ES + ((modrm >> 3) & 3);
					values[sreg] = modrm >> 6 == 3 ? values[modrm & 7] : null;
					return true;
				}
				case 0x89 -> { // MOV r/m16,r16
					int modrm = b[i + 1] & 0xff;
					Value value = values[(modrm >> 3) & 7];
					if (modrm >> 6 == 3) {
						values[modrm & 7] = value;
					}
					else {
						store(instruction, slot(b, i + 1, segment), value);
					}
					return true;
				}
				case 0x8b -> { // MOV r16,r/m16
					int modrm = b[i + 1] & 0xff;
					values[(modrm >> 3) & 7] = modrm >> 6 == 3 ? values[modrm & 7] : null;
					return true;
				}
				case 0xc7 -> { // MOV r/m16,imm16
					int modrm = b[i + 1] & 0xff;
					if (((modrm >> 3) & 7) != 0) {
						return false;
					}
					Value value = new Constant(X86.word(b, b.length - 2));
					if (modrm >> 6 == 3) {
						values[modrm & 7] = value;
					}
					else {
						store(instruction, slot(b, i + 1, segment), value);
					}
					return true;
				}
				case 0x87 -> { // XCHG r/m16,r16
					int modrm = b[i + 1] & 0xff;
					int reg = (modrm >> 3) & 7;
					if (modrm >> 6 == 3) {
						Value swap = values[modrm & 7];
						values[modrm & 7] = values[reg];
						values[reg] = swap;
					}
					else {
						Slot slot = slot(b, i + 1, segment);
						Value old = slots.get(slot);
						store(instruction, slot, values[reg]);
						values[reg] = old;
					}
					return true;
				}
				case 0xa3 -> { // MOV moffs16,AX
					store(instruction, new Slot(segmentOrImplied(segment, false), DIRECT,
						X86.word(b, i + 1)), values[AX]);
					return true;
				}
				case 0x06, 0x0e, 0x16, 0x1e -> { // PUSH sreg
					stack.push(nullable(segmentValue(op >> 3)));
					return true;
				}
				case 0x07, 0x17, 0x1f -> { // POP sreg
					values[ES + (op >> 3)] = popValue();
					return true;
				}
				case 0x68 -> { // PUSH imm16
					stack.push(new Constant(X86.word(b, i + 1)));
					return true;
				}
				case 0xcd -> { // INT n
					if ((b[i + 1] & 0xff) == 0x21 && values[AX] instanceof Constant(int ax) &&
						(ax >> 8) == 0x25 && values[DS] instanceof HoldsCs &&
						values[DX] instanceof Constant(int dx)) {
						target(instruction, dx);
					}
					return false;
				}
				default -> {
					if (op >= 0x50 && op <= 0x57) { // PUSH r16
						stack.push(nullable(values[op - 0x50]));
						return true;
					}
					if (op >= 0x58 && op <= 0x5f) { // POP r16
						values[op - 0x58] = popValue();
						return true;
					}
					if (instruction.getFlowType().isCall()) {
						call(instruction);
						return true;
					}
					return false;
				}
			}
		}

		/** A call: check for a pair handed to a storer, then keep only a DS it preserves. */
		private void call(Instruction instruction) {
			Value ds = values[DS];
			Function callee = null;
			for (Address flow : instruction.getFlows()) {
				callee = program.getFunctionManager().getFunctionAt(flow);
			}
			if (callee != null && ds instanceof HoldsCs && values[DX] instanceof Constant(int dx) &&
				storesDsDxPair(callee)) {
				target(instruction, dx);
			}
			reset();
			if (callee != null && !writesDs(callee)) {
				values[DS] = ds;
			}
		}

		private boolean storesDsDxPair(Function callee) {
			return pairStorers.computeIfAbsent(callee.getEntryPoint(), _ -> {
				Map<Slot, Integer> stored = new HashMap<>(); // slot -> 0 for DX, 1 for DS
				for (Instruction insn : program.getListing().getInstructions(callee.getBody(), true)) {
					byte[] b = X86.bytes(insn);
					int i = X86.opcodeIndex(b);
					if (i < 0 || i + 1 >= b.length || ((b[i + 1] & 0xff) >> 6) == 3) {
						continue;
					}
					int segment = X86.segmentOverride(b);
					int op = b[i] & 0xff;
					int reg = ((b[i + 1] & 0xff) >> 3) & 7;
					if (op == 0x89 && reg == DX) {
						stored.put(slot(b, i + 1, segment), 0);
					}
					else if (op == 0x8c && reg == DS - ES) {
						stored.put(slot(b, i + 1, segment), 1);
					}
				}
				for (Map.Entry<Slot, Integer> e : stored.entrySet()) {
					if (e.getValue() == 0 && Integer.valueOf(1).equals(stored.get(e.getKey().next()))) {
						return true;
					}
				}
				return false;
			});
		}

		private boolean writesDs(Function callee) {
			return dsWriters.computeIfAbsent(callee.getEntryPoint(), _ -> {
				for (Instruction insn : program.getListing().getInstructions(callee.getBody(), true)) {
					for (Object result : insn.getResultObjects()) {
						if (result instanceof Register written && X86.overlaps(written, registers[DS])) {
							return true;
						}
					}
				}
				return false;
			});
		}

		private void store(Instruction instruction, Slot slot, Value value) {
			if (value == null) {
				slots.remove(slot);
				return;
			}
			slots.put(slot, value);
			if (value instanceof Constant(int offset) && slots.get(slot.next()) instanceof HoldsCs) {
				target(instruction, offset);
			}
			else if (value instanceof HoldsCs &&
				slots.get(slot.previous()) instanceof Constant(int offset)) {
				target(instruction, offset);
			}
		}

		private void target(Instruction instruction, int offset) {
			if (!(instruction.getMinAddress() instanceof SegmentedAddress at)) {
				return;
			}
			Address target = ((SegmentedAddressSpace) at.getAddressSpace())
					.getAddress(X86.codeSegment(program, instruction, at), offset & 0xffff);
			MemoryBlock block = program.getMemory().getBlock(target);
			if (block != null && block.isExecute() && block.isInitialized()) {
				targets.putIfAbsent(target, instruction);
			}
		}

		private void invalidateWrites(Instruction instruction) {
			for (Object result : instruction.getResultObjects()) {
				if (!(result instanceof Register written)) {
					continue;
				}
				for (int r = 0; r < registers.length; r++) {
					if (r != CS && X86.overlaps(written, registers[r])) {
						values[r] = null;
					}
				}
				if (X86.overlaps(written, registers[4])) { // SP: the stack model no longer holds
					stack.clear();
				}
			}
		}

		private Value segmentValue(int sreg) {
			return sreg == 1 ? CS_VALUE : values[ES + sreg];
		}

		private Value popValue() {
			if (stack.isEmpty()) {
				return null;
			}
			Value value = stack.pop();
			return value == UNKNOWN ? null : value;
		}

		private static Value nullable(Value value) {
			return value == null ? UNKNOWN : value;
		}
	}

	/** A stack placeholder for a value nothing is known about (deques refuse null). */
	private static final Value UNKNOWN = new Constant(Integer.MIN_VALUE);

	private static final int BX = 3;
	private static final int BP = 5;
	private static final int SI = 6;
	private static final int DI = 7;

	/** The registers a 16-bit ModRM can address through. */
	private static final int[] ADDRESS_REGISTERS = { BX, BP, SI, DI };

	/** True if {@code slot}'s 16-bit ModRM r/m field addresses through register {@code reg}. */
	private static boolean addressesThrough(Slot slot, int reg) {
		return switch (slot.base()) {
			case 0 -> reg == BX || reg == SI; // [BX+SI]
			case 1 -> reg == BX || reg == DI; // [BX+DI]
			case 2 -> reg == BP || reg == SI; // [BP+SI]
			case 3 -> reg == BP || reg == DI; // [BP+DI]
			case 4 -> reg == SI;
			case 5 -> reg == DI;
			case 6 -> reg == BP;
			case 7 -> reg == BX;
			default -> false; // DIRECT
		};
	}

	/** The memory word a 16-bit ModRM at {@code b[m]} addresses. */
	private static Slot slot(byte[] b, int m, int segment) {
		int modrm = b[m] & 0xff;
		int mod = modrm >> 6;
		int rm = modrm & 7;
		if (mod == 0 && rm == 6) {
			return new Slot(segmentOrImplied(segment, false), DIRECT, X86.word(b, m + 1));
		}
		boolean stackBased = rm == 2 || rm == 3 || rm == 6;
		int disp = switch (mod) {
			case 1 -> b[m + 1];
			case 2 -> (short) X86.word(b, m + 1);
			default -> 0;
		};
		return new Slot(segmentOrImplied(segment, stackBased), rm, disp);
	}

	private static int segmentOrImplied(int segment, boolean stackBased) {
		if (segment != 0) {
			return segment;
		}
		return stackBased ? 0x36 : 0x3e;
	}

}
