package ebbex.rtlink;

import java.util.function.Predicate;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Whether an instruction is real code on its own evidence. The passes that clear junk — the
 * buried-code repair and the VM dispatch resolver — must agree on this exactly, or one would
 * clear what the other has just proved, so they share it.
 */
final class CodeEvidence {

	private CodeEvidence() {
	}

	/**
	 * True if {@code instruction} stands on its own evidence as real code: a flow reference to
	 * its entry, a function entry, an external entry point, or a non-default symbol. Function
	 * <i>containment</i> is deliberately not evidence — junk gets absorbed into function bodies.
	 */
	static boolean isEvidenced(Program program, Instruction instruction) {
		Address entry = instruction.getMinAddress();
		if (hasFlowReferenceTo(program, entry)) {
			return true;
		}
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			return true;
		}
		if (program.getSymbolTable().isExternalEntryPoint(entry)) {
			return true;
		}
		Symbol primary = program.getSymbolTable().getPrimarySymbol(entry);
		return primary != null && primary.getSource() != SourceType.DEFAULT;
	}

	/** True if any flow reference — call, jump, fall-through override — reaches {@code address}. */
	static boolean hasFlowReferenceTo(Program program, Address address) {
		return hasReferenceTo(program, address, RefType::isFlow);
	}

	/** True if a reference whose type {@code kind} accepts reaches {@code address}. */
	static boolean hasReferenceTo(Program program, Address address, Predicate<RefType> kind) {
		for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
			if (kind.test(reference.getReferenceType())) {
				return true;
			}
		}
		return false;
	}

	/** True if a reference whose type {@code kind} accepts goes from {@code source} to {@code target}. */
	static boolean refersTo(Instruction source, Address target, Predicate<RefType> kind) {
		for (Reference reference : source.getReferencesFrom()) {
			if (reference.getToAddress().equals(target) && kind.test(reference.getReferenceType())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Create a function at {@code target} when it holds an instruction, no function owns it,
	 * and something calls it: recovered code with the strongest evidence there is.
	 */
	static void promoteIfCalled(Program program, Address target, TaskMonitor monitor) {
		if (program.getListing().getInstructionAt(target) != null &&
			program.getFunctionManager().getFunctionContaining(target) == null &&
			hasReferenceTo(program, target, RefType::isCall)) {
			new CreateFunctionCmd(target).applyTo(program, monitor);
		}
	}
}
