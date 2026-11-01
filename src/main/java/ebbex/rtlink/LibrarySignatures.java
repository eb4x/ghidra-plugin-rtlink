package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ebbex.rtlink.OmfLibrary.Module;
import ebbex.rtlink.OmfLibrary.Public;
import ebbex.rtlink.OmfLibrary.Segment;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Places the public symbols of a vendor object library in a program by matching their
 * bytes, and names (and, for code, decodes and makes functions of) what it places. See
 * {@code docs/vendor-signatures.md}.
 * <p>
 * A body is the bytes from one public to the next in its segment. Bytes a fixup patches, or
 * no data record gives, are never compared. A module whose segment matches whole, at exactly
 * one place, places every public in it. Otherwise each public is matched by its
 * <i>opening</i>: its first instructions, decoded from the vendor bytes, up to
 * {@value #OPENING_COMPARED} compared bytes, with the displacements of relative branches
 * masked too — build variants move code, so a {@code JNZ} keeps its opcode but not its
 * distance. An opening matching at exactly one place is a candidate; the candidates in the
 * block holding most of them, in vendor order, are kept; and the remaining publics are placed
 * only next to a kept neighbour, at the distance the module gives them, where their opening
 * matches there. Of modules placing the same name (the nucleus ships in nine build variants),
 * the one placing most publics wins.
 */
final class LibrarySignatures {

	/** Compared bytes a pattern needs before a unique match counts. */
	static final int MIN_COMPARED = 8;

	/** Compared bytes of a public's opening. */
	static final int OPENING_COMPARED = 24;

	/** What was placed: entries named, and of those, functions made. */
	record Result(int placed, int functions) {
	}

	/** Bytes to look for, and which of them not to compare. */
	private record Pattern(byte[] data, boolean[] masked) {
		int length() {
			return data.length;
		}

		int compared() {
			int n = 0;
			for (boolean m : masked) {
				n += m ? 0 : 1;
			}
			return n;
		}
	}

	/**
	 * The publics at one offset of a segment and their openings (each bounded by the next
	 * public), shortest first: where entries share a prologue ({@code $$VM_CALL} and
	 * {@code $$VM_JMP}) only a longer one tells them apart.
	 */
	private record Body(int offset, List<String> names, List<Pattern> openings) {
		Pattern opening() {
			return openings.get(0);
		}
	}

	/**
	 * Compared bytes of the successively longer openings tried when a shorter one is not
	 * unique. The first is shorter than {@value #OPENING_COMPARED}: an entry whose variant
	 * changes its body a few instructions in ({@code $$VM_RET}'s neighbours) still matches by
	 * its first instructions between two placed neighbours, where little else can.
	 */
	private static final int[] OPENING_STEPS = { 12, OPENING_COMPARED, 48, 96 };

	/** A public placed at {@code address}: every name sharing its offset, in order. */
	/**
	 * Where a public name is placed and how many entries its module placed in all. The module
	 * that places more of itself wins a name both claim; the first one wins a tie.
	 */
	private record Winner(Placement placement, int score) {
		static Winner better(Winner held, Winner challenger) {
			return challenger.score() > held.score() ? challenger : held;
		}
	}

	private record Placement(Address address, List<String> names) {
	}

	/** A resident code block's bytes. */
	private record Region(Address start, byte[] bytes) {
	}

	private LibrarySignatures() {
	}

	static Result apply(Program program, List<Module> modules, TaskMonitor monitor)
			throws CancelledException {
		List<Region> regions = regions(program);
		if (regions.isEmpty()) {
			return new Result(0, 0);
		}
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		Address scratch = regions.get(0).start();
		Map<String, Winner> byName = new LinkedHashMap<>();
		for (Module module : modules) {
			monitor.checkCancelled();
			List<Placement> placed = place(regions, module, pseudo, scratch, monitor);
			for (Placement placement : placed) {
				for (String name : placement.names()) {
					byName.merge(name, new Winner(placement, placed.size()), Winner::better);
				}
			}
		}
		// Names a winning module places together stay together, aliases in vendor order.
		Map<Address, List<String>> byAddress = new TreeMap<>();
		for (Map.Entry<String, Winner> e : byName.entrySet()) {
			List<String> names = byAddress.computeIfAbsent(
				e.getValue().placement().address(), _ -> new ArrayList<>());
			if (!names.contains(e.getKey())) {
				names.add(e.getKey());
			}
		}

		int placed = 0;
		int functions = 0;
		for (Map.Entry<Address, List<String>> e : byAddress.entrySet()) {
			monitor.checkCancelled();
			Address at = e.getKey();
			boolean code = isCode(program, pseudo, at);
			// One line each: a match this wide is worth being able to audit.
			Msg.info(LibrarySignatures.class, String.format("RTLink/Plus: %s %s %s", at,
				code ? "code" : "data", e.getValue()));
			if (code && claimCode(program, at, monitor)) {
				functions++;
			}
			if (name(program, at, e.getValue(), code)) {
				placed++;
			}
		}
		return new Result(placed, functions);
	}

	// ---------------------------------------------------------------------------- matching

	private static List<Placement> place(List<Region> regions, Module module,
			PseudoDisassembler pseudo, Address scratch, TaskMonitor monitor)
			throws CancelledException {
		List<Placement> placed = new ArrayList<>();
		for (Segment segment : module.segments()) {
			monitor.checkCancelled();
			List<Body> bodies = bodies(module, segment, pseudo, scratch);
			if (bodies.isEmpty()) {
				continue;
			}
			Address whole = wholeSegment(regions, segment);
			if (whole != null) {
				for (Body body : bodies) {
					placed.add(new Placement(whole.add(body.offset()), body.names()));
				}
				continue;
			}
			placed.addAll(publicByPublic(regions, bodies));
		}
		return placed;
	}

	/** Where the whole segment matches, if at exactly one place. */
	private static Address wholeSegment(List<Region> regions, Segment segment) {
		Pattern all = slice(segment, 0, segment.data().length);
		if (all.length() == 0 || all.compared() < MIN_COMPARED) {
			return null;
		}
		List<Address> found = find(regions, all, 2);
		return found.size() == 1 ? found.get(0) : null;
	}

	private static List<Placement> publicByPublic(List<Region> regions, List<Body> bodies) {
		// Candidates: unique matches of openings long enough to be told apart.
		Map<Body, Address> candidates = new LinkedHashMap<>();
		for (Body body : bodies) {
			for (Pattern opening : body.openings()) {
				if (opening.compared() < MIN_COMPARED) {
					continue;
				}
				List<Address> found = find(regions, opening, 2);
				if (found.size() == 1) {
					candidates.put(body, found.get(0));
				}
				if (found.size() <= 1) {
					break; // unique, or a longer opening will not match either
				}
			}
		}
		// The block most of them land in, and of those the longest run in vendor order.
		Map<Region, Integer> votes = new LinkedHashMap<>();
		for (Address address : candidates.values()) {
			votes.merge(regionOf(regions, address), 1, Integer::sum);
		}
		Region home = votes.entrySet().stream().max(Map.Entry.comparingByValue())
				.map(Map.Entry::getKey).orElse(null);
		if (home == null) {
			return List.of();
		}
		List<Body> ordered = new ArrayList<>();
		for (Body body : bodies) {
			Address address = candidates.get(body);
			if (address != null && regionOf(regions, address) == home) {
				ordered.add(body);
			}
		}
		Map<Body, Address> kept = new LinkedHashMap<>();
		for (Body body : increasingRun(ordered, candidates)) {
			kept.put(body, candidates.get(body));
		}

		// The rest, beside a kept neighbour, until nothing more fits.
		boolean grew = true;
		while (grew) {
			grew = false;
			for (int i = 0; i < bodies.size(); i++) {
				if (kept.containsKey(bodies.get(i))) {
					continue;
				}
				Address at = besideNeighbour(home, bodies, i, kept);
				if (at != null) {
					kept.put(bodies.get(i), at);
					grew = true;
				}
			}
		}
		List<Placement> placed = new ArrayList<>();
		for (Body body : bodies) {
			Address address = kept.get(body);
			if (address != null) {
				placed.add(new Placement(address, body.names()));
			}
		}
		return placed;
	}

	/**
	 * Where public {@code i}'s opening matches at its module distance from the kept public
	 * before it, or failing that from the kept public after it, between the two. Order bounds
	 * it, not the neighbours' lengths: a variant's bodies run longer or shorter.
	 */
	private static Address besideNeighbour(Region home, List<Body> bodies, int i,
			Map<Body, Address> kept) {
		Body body = bodies.get(i);
		Body before = null;
		for (int j = i - 1; j >= 0 && before == null; j--) {
			before = kept.containsKey(bodies.get(j)) ? bodies.get(j) : null;
		}
		Body after = null;
		for (int j = i + 1; j < bodies.size() && after == null; j++) {
			after = kept.containsKey(bodies.get(j)) ? bodies.get(j) : null;
		}
		List<Address> tries = new ArrayList<>();
		if (before != null) {
			tries.add(kept.get(before).add(body.offset() - before.offset()));
		}
		if (after != null) {
			long back = after.offset() - body.offset();
			if (kept.get(after).getOffset() - home.start().getOffset() >= back) {
				tries.add(kept.get(after).subtract(back));
			}
		}
		for (Address at : tries) {
			if (before != null && at.compareTo(kept.get(before)) <= 0) {
				continue;
			}
			if (after != null && at.compareTo(kept.get(after)) >= 0) {
				continue;
			}
			if (body.opening().length() > 0 && matchesAt(home, at, body.opening())) {
				return at;
			}
		}
		if (before == null || after == null) {
			return null;
		}
		// Between two kept neighbours, the one place the opening matches, lengthened until
		// only one is left (or none).
		for (Pattern opening : body.openings()) {
			if (opening.length() == 0) {
				break;
			}
			List<Address> found = findBetween(home, opening, kept.get(before).add(1),
				kept.get(after));
			if (found.size() == 1) {
				return found.get(0);
			}
			if (found.isEmpty()) {
				break;
			}
		}
		return null;
	}

	/** Where {@code pattern} matches in {@code region} at {@code low} or later, ending by {@code high}. */
	private static List<Address> findBetween(Region region, Pattern pattern, Address low,
			Address high) {
		List<Address> found = new ArrayList<>();
		long from = low.getOffset() - region.start().getOffset();
		long to = high.getOffset() - region.start().getOffset() - pattern.length();
		for (long at = Math.max(0, from); at <= to && found.size() < 2; at++) {
			if (at + pattern.length() <= region.bytes().length &&
				matches(region.bytes(), (int) at, pattern)) {
				found.add(region.start().add(at));
			}
		}
		return found;
	}

	/** The longest subsequence of {@code ordered} (vendor order) whose addresses increase. */
	private static List<Body> increasingRun(List<Body> ordered, Map<Body, Address> at) {
		int n = ordered.size();
		int[] length = new int[n];
		int[] previous = new int[n];
		int best = -1;
		for (int i = 0; i < n; i++) {
			length[i] = 1;
			previous[i] = -1;
			for (int j = 0; j < i; j++) {
				if (at.get(ordered.get(j)).compareTo(at.get(ordered.get(i))) < 0 &&
					length[j] + 1 > length[i]) {
					length[i] = length[j] + 1;
					previous[i] = j;
				}
			}
			if (best < 0 || length[i] > length[best]) {
				best = i;
			}
		}
		List<Body> run = new ArrayList<>();
		for (int i = best; i >= 0; i = previous[i]) {
			run.add(0, ordered.get(i));
		}
		return run;
	}

	/** The segment's publics: aliases share one body, each runs to the next. */
	private static List<Body> bodies(Module module, Segment segment, PseudoDisassembler pseudo,
			Address scratch) {
		TreeMap<Long, List<String>> atOffset = new TreeMap<>();
		for (Public p : module.publics()) {
			if (p.segment() == segment.index() && p.offset() < segment.data().length) {
				atOffset.computeIfAbsent(p.offset(), _ -> new ArrayList<>()).add(p.name());
			}
		}
		List<Body> bodies = new ArrayList<>();
		List<Long> offsets = new ArrayList<>(atOffset.keySet());
		for (int i = 0; i < offsets.size(); i++) {
			int offset = offsets.get(i).intValue();
			int end = i + 1 < offsets.size() ? offsets.get(i + 1).intValue() : segment.data().length;
			List<Pattern> openings = new ArrayList<>();
			for (int compared : OPENING_STEPS) {
				Pattern opening = opening(segment, offset, end, compared, pseudo, scratch);
				if (!openings.isEmpty() &&
					opening.length() == openings.get(openings.size() - 1).length()) {
					break; // the body ended: no longer opening to be had
				}
				openings.add(opening);
			}
			bodies.add(new Body(offset, atOffset.get(offsets.get(i)), openings));
		}
		return bodies;
	}

	/**
	 * The first instructions at {@code offset}, decoded from the vendor bytes, until
	 * {@code wanted} bytes are compared, the body ends, or an instruction leaves the entry's
	 * straight line (a return or jump: what follows may be a variable, as {@code $$VM_RET}'s
	 * word after its {@code RETF} is in VICEROY); relative branch displacements masked.
	 * Empty where the bytes do not decode (a data public).
	 */
	private static Pattern opening(Segment segment, int offset, int end, int wanted,
			PseudoDisassembler pseudo, Address scratch) {
		Pattern body = slice(segment, offset, end);
		int at = 0;
		int compared = 0;
		while (at < body.length() && compared < wanted) {
			PseudoInstruction instruction = decode(pseudo, scratch, body.data(), at);
			if (instruction == null || at + instruction.getLength() > body.length()) {
				break;
			}
			int length = instruction.getLength();
			maskDisplacement(body, at, length);
			for (int i = at; i < at + length; i++) {
				compared += body.masked()[i] ? 0 : 1;
			}
			at += length;
			if (!instruction.getFlowType().hasFallthrough()) {
				break;
			}
		}
		return new Pattern(Arrays.copyOf(body.data(), at),
			Arrays.copyOf(body.masked(), at));
	}

	private static PseudoInstruction decode(PseudoDisassembler pseudo, Address scratch,
			byte[] bytes, int at) {
		try {
			byte[] window = Arrays.copyOfRange(bytes, at, Math.min(bytes.length, at + 16));
			return pseudo.disassemble(scratch, window);
		}
		catch (Exception _) {
			return null;
		}
	}

	/** Mask the displacement of a relative jump, call, loop or Jcc at {@code data[at]}. */
	private static void maskDisplacement(Pattern pattern, int at, int length) {
		byte[] data = pattern.data();
		int i = at;
		while (i < at + length && X86.isPrefix(data[i] & 0xff)) {
			i++;
		}
		if (i >= at + length) {
			return;
		}
		int op = data[i] & 0xff;
		int displacement = 0;
		if ((op >= 0x70 && op <= 0x7f) || op == 0xeb || (op >= 0xe0 && op <= 0xe3)) {
			displacement = 1;
		}
		else if (op == 0xe8 || op == 0xe9) {
			displacement = 2;
		}
		else if (op == 0x0f && i + 1 < at + length && ((data[i + 1] & 0xf0) == 0x80)) {
			displacement = 2;
		}
		for (int k = at + length - displacement; k < at + length; k++) {
			pattern.masked()[k] = true;
		}
	}

	/** {@code segment[offset, end)} with its masks, less the masked bytes at the end. */
	private static Pattern slice(Segment segment, int offset, int end) {
		int last = end;
		while (last > offset && segment.masked(last - 1)) {
			last--;
		}
		byte[] data = Arrays.copyOfRange(segment.data(), offset, last);
		boolean[] masked = new boolean[data.length];
		for (int i = 0; i < data.length; i++) {
			masked[i] = segment.masked(offset + i);
		}
		return new Pattern(data, masked);
	}

	/** Up to {@code limit} places the pattern matches. */
	private static List<Address> find(List<Region> regions, Pattern pattern, int limit) {
		List<Address> found = new ArrayList<>();
		int first = 0;
		while (first < pattern.length() && pattern.masked()[first]) {
			first++;
		}
		if (first == pattern.length()) {
			return found;
		}
		byte anchor = pattern.data()[first];
		for (Region region : regions) {
			byte[] bytes = region.bytes();
			for (int at = 0; at + pattern.length() <= bytes.length; at++) {
				if (bytes[at + first] == anchor && matches(bytes, at, pattern)) {
					found.add(region.start().add(at));
					if (found.size() >= limit) {
						return found;
					}
				}
			}
		}
		return found;
	}

	private static boolean matchesAt(Region region, Address at, Pattern pattern) {
		long index = at.getOffset() - region.start().getOffset();
		return index >= 0 && index + pattern.length() <= region.bytes().length &&
			matches(region.bytes(), (int) index, pattern);
	}

	private static boolean matches(byte[] bytes, int at, Pattern pattern) {
		for (int i = 0; i < pattern.length(); i++) {
			if (!pattern.masked()[i] && bytes[at + i] != pattern.data()[i]) {
				return false;
			}
		}
		return true;
	}

	private static List<Region> regions(Program program) {
		List<Region> regions = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isExecute() || !block.isInitialized() ||
				!(block.getStart() instanceof SegmentedAddress) || block.getSize() > 0x100000) {
				continue; // resident code only: the runtime is not overlaid
			}
			byte[] bytes = new byte[(int) block.getSize()];
			try {
				block.getBytes(block.getStart(), bytes);
			}
			catch (MemoryAccessException _) {
				continue;
			}
			regions.add(new Region(block.getStart(), bytes));
		}
		return regions;
	}

	private static Region regionOf(List<Region> regions, Address address) {
		for (Region region : regions) {
			long index = address.getOffset() - region.start().getOffset();
			if (index >= 0 && index < region.bytes().length) {
				return region;
			}
		}
		return null;
	}

	// ---------------------------------------------------------------------------- applying

	/**
	 * Whether a placed public is code, by what the program's own analysis has made of it: an
	 * instruction starts there; or the bytes are undefined, their first word is not zero, an
	 * instruction decodes there, and nothing reads or writes them as data. The nucleus keeps
	 * its variables in its code segment ({@code $$VMFLAGS}, read as {@code CS:[...]}), and
	 * RTLUTILS its messages ({@code $$RTLCOMMON_MESSAGES}): those get a label only.
	 */
	private static boolean isCode(Program program, PseudoDisassembler pseudo, Address at) {
		Listing listing = program.getListing();
		if (listing.getInstructionAt(at) != null) {
			return true;
		}
		if (listing.getInstructionContaining(at) != null ||
			listing.getDefinedDataContaining(at) != null) {
			return false;
		}
		for (Reference reference : program.getReferenceManager().getReferencesTo(at)) {
			if (reference.getReferenceType().isData()) {
				return false;
			}
		}
		try {
			return program.getMemory().getShort(at) != 0 && pseudo.disassemble(at) != null;
		}
		catch (Exception _) {
			return false;
		}
	}

	/**
	 * Decode at {@code entry} and make it a function; true if a function was made. Never
	 * inside another function's body: a variant may enter a routine ahead of the vendor's
	 * public (VICEROY's {@code $$VMFLUSHALL} has a flag test in front of it at {@code 1aae},
	 * where its callers call), and the program's own partition stands; the name goes on as a
	 * label.
	 */
	private static boolean claimCode(Program program, Address entry, TaskMonitor monitor) {
		Function containing = program.getFunctionManager().getFunctionContaining(entry);
		if (containing != null && !containing.getEntryPoint().equals(entry)) {
			return false;
		}
		Listing listing = program.getListing();
		if (listing.getInstructionAt(entry) == null) {
			new DisassembleCommand(entry, null, true).applyTo(program, monitor);
			if (listing.getInstructionAt(entry) == null) {
				return false;
			}
		}
		if (program.getFunctionManager().getFunctionAt(entry) != null) {
			return false;
		}
		return new CreateFunctionCmd(entry).applyTo(program, monitor);
	}

	/**
	 * Name the address: a default-named function takes the first name, every other name
	 * becomes a label beside whatever name the address already has. Nothing a user named is
	 * renamed. True if any name was new.
	 */
	private static boolean name(Program program, Address at, List<String> names, boolean code) {
		SymbolTable symbols = program.getSymbolTable();
		boolean added = false;
		for (String name : names) {
			if (hasName(symbols, at, name)) {
				continue;
			}
			try {
				Function function = program.getFunctionManager().getFunctionAt(at);
				if (code && function != null &&
					function.getSymbol().getSource() == SourceType.DEFAULT) {
					function.setName(name, SourceType.IMPORTED);
				}
				else {
					symbols.createLabel(at, name, SourceType.IMPORTED);
				}
				added = true;
			}
			catch (Exception e) {
				Msg.debug(LibrarySignatures.class,
					"RTLink: cannot name " + at + " " + name + ": " + e.getMessage());
			}
		}
		return added;
	}

	private static boolean hasName(SymbolTable symbols, Address at, String name) {
		for (Symbol symbol : symbols.getSymbols(at)) {
			if (symbol.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}
}
