package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Predicate;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
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

	/** True if an instruction already decoded covers {@code at} without starting there. */
	static boolean splitsInstruction(Program program, Address at) {
		Instruction covering = program.getListing().getInstructionContaining(at);
		return covering != null && !covering.getMinAddress().equals(at);
	}

	/** The instruction just before {@code at} if it falls through to {@code at}, else null. */
	static Instruction fallingInto(Program program, Address at) {
		Address before = at.previous();
		Instruction previous =
			before == null ? null : program.getListing().getInstructionContaining(before);
		return previous != null && at.equals(previous.getFallThrough()) ? previous : null;
	}

	/**
	 * Disassemble from {@code at} with auto-analysis off, for a repair that has to finish
	 * before analysis sees any of it; returns what was decoded.
	 */
	static AddressSetView decodeQuietly(Program program, Address at, TaskMonitor monitor) {
		DisassembleCommand disassemble = new DisassembleCommand(at, null, true);
		disassemble.enableCodeAnalysis(false);
		disassemble.applyTo(program, monitor);
		return disassemble.getDisassembledAddressSet();
	}

	/** Rounds of clearing and re-decoding; each one gets past one more guessed string. */
	private static final int GUESS_ROUNDS = 16;

	/**
	 * Disassemble from {@code seeds} following flow, and decode through any string the string
	 * search guessed where that flow runs. The passes that decode late (far pointers, far
	 * vectors) reach code long after the string search has run over bytes nothing had decoded
	 * yet, and a guess there blocks the flow ("conflicting data"; VICEROY {@code 210d:152b},
	 * one byte early, on a {@code JMP}'s displacement). Flow from code is better evidence than
	 * a guess, so a string with a default name and no reference to its start is cleared, its
	 * conflict mark dropped, and the flow decoded on. Any other data stops the flow, as before.
	 */
	static AddressSet disassembleOverGuesses(Program program, AddressSetView seeds,
			TaskMonitor monitor) {
		AddressSet decoded = new AddressSet();
		AddressSetView next = seeds;
		long cleared = 0;
		for (int round = 0; round < GUESS_ROUNDS && !next.isEmpty(); round++) {
			DisassembleCommand disassemble = new DisassembleCommand(next, null, true);
			disassemble.applyTo(program, monitor);
			AddressSetView fresh = disassemble.getDisassembledAddressSet();
			if (fresh == null || fresh.isEmpty()) {
				break;
			}
			decoded.add(fresh);
			next = clearGuessesBlocking(program, fresh);
			cleared += next.getNumAddresses();
		}
		RTLinkProgram.report(RTLinkFlowRepairAnalyzer.class, cleared,
			"RTLink/Plus: Decoded through %d guessed string(s) in the way of recovered code");
		return decoded;
	}

	/** Clear the guessed strings that block a flow out of {@code decoded}; returns the flows. */
	private static AddressSet clearGuessesBlocking(Program program, AddressSetView decoded) {
		Listing listing = program.getListing();
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		AddressSet blocked = new AddressSet();
		for (Instruction instruction : listing.getInstructions(decoded, true)) {
			List<Address> targets = new ArrayList<>(List.of(instruction.getFlows()));
			if (instruction.getFallThrough() != null) {
				targets.add(instruction.getFallThrough());
			}
			for (Address target : targets) {
				if (listing.getInstructionContaining(target) != null) {
					continue;
				}
				PseudoInstruction would = CodeSeeds.decode(pseudo, target);
				if (would == null) {
					continue;
				}
				List<Data> guesses = guessedStrings(program, target, would.getMaxAddress());
				if (guesses.isEmpty()) {
					continue;
				}
				for (Data guess : guesses) {
					listing.clearCodeUnits(guess.getMinAddress(), guess.getMaxAddress(), false);
				}
				removeDataConflictMarks(program, target);
				blocked.add(target);
			}
		}
		return blocked;
	}

	/**
	 * The defined data over {@code [start, end]} if every item is a guessed string, else none:
	 * one item that is not (other data, a name, a reference to it) means the bytes are not
	 * ours to take.
	 */
	private static List<Data> guessedStrings(Program program, Address start, Address end) {
		Listing listing = program.getListing();
		Map<Address, Data> data = new TreeMap<>();
		Data covering = listing.getDefinedDataContaining(start);
		if (covering != null) {
			data.put(covering.getMinAddress(), covering);
		}
		for (Data item : listing.getDefinedData(new AddressSet(start, end), true)) {
			data.put(item.getMinAddress(), item);
		}
		for (Data item : data.values()) {
			Symbol name = program.getSymbolTable().getPrimarySymbol(item.getMinAddress());
			if (!item.hasStringValue() || (name != null && name.getSource() != SourceType.DEFAULT) ||
				program.getReferenceManager().hasReferencesTo(item.getMinAddress())) {
				return List.of();
			}
		}
		return List.copyOf(data.values());
	}

	/** Drop the disassembler's "conflicting data" mark at {@code at}. */
	private static void removeDataConflictMarks(Program program, Address at) {
		BookmarkManager bookmarks = program.getBookmarkManager();
		for (Bookmark bookmark : bookmarks.getBookmarks(at, BookmarkType.ERROR)) {
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				bookmark.getComment().contains("conflicting data")) {
				bookmarks.removeBookmark(bookmark);
			}
		}
	}

	/** Create a function at {@code at} unless one already contains it; true if one was made. */
	static boolean makeFunction(Program program, Address at, TaskMonitor monitor) {
		return program.getFunctionManager().getFunctionContaining(at) == null &&
			new CreateFunctionCmd(at).applyTo(program, monitor);
	}

	/**
	 * Every instruction that calls {@code function}, directly or through one of its thunks, in
	 * a list copied up front: a caller about to change references must not iterate them live
	 * (past 1700 references to one address the iterator is live rather than a snapshot).
	 */
	static List<Instruction> callsTo(Program program, Function function) {
		List<Address> entries = new ArrayList<>(List.of(function.getEntryPoint()));
		Address[] thunks = function.getFunctionThunkAddresses(true);
		if (thunks != null) {
			entries.addAll(List.of(thunks));
		}
		List<Instruction> calls = new ArrayList<>();
		for (Address entry : entries) {
			for (Reference reference : program.getReferenceManager().getReferencesTo(entry)) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = program.getListing().getInstructionAt(reference.getFromAddress());
				if (call != null) {
					calls.add(call);
				}
			}
		}
		return calls;
	}

	/**
	 * Create a function at {@code target} when it holds an instruction, no function owns it,
	 * and something calls it: recovered code with the strongest evidence there is.
	 */
	static void promoteIfCalled(Program program, Address target, TaskMonitor monitor) {
		if (program.getListing().getInstructionAt(target) != null &&
			hasReferenceTo(program, target, RefType::isCall)) {
			makeFunction(program, target, monitor);
		}
	}
}
