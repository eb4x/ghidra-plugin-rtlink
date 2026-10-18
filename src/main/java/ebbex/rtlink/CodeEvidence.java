package ebbex.rtlink;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

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
		for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
			if (reference.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}
}
