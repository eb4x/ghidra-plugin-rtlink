package ebbex.rtlink;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The disassembler's own ERROR marks ("Bad Instruction"): where they lie for a stretch of
 * junk, and sweeping the ones a repair has made stale. The disassembler never takes a mark
 * back, so every pass that clears or re-decodes code has to.
 */
final class ErrorMarks {

	private ErrorMarks() {
	}

	/**
	 * The junk's addresses plus the byte after it: a run the disassembler abandoned leaves its
	 * ERROR mark one past the last instruction it managed to decode, so the mark lies just
	 * outside the junk itself. Only a bookmark sweep may reach that byte — clearing it would
	 * take the next real instruction with it.
	 */
	static AddressSetView markedRange(AddressSetView junk) {
		AddressSet marked = new AddressSet(junk);
		Address after = junk.getMaxAddress().next();
		if (after != null) {
			marked.add(after, after);
		}
		return marked;
	}

	/** The disassembler's ERROR marks that {@code keep} accepts, collected before any is removed. */
	static List<Bookmark> collect(Program program, Predicate<Bookmark> keep, TaskMonitor monitor)
			throws CancelledException {
		List<Bookmark> marks = new ArrayList<>();
		Iterator<Bookmark> iterator =
			program.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Bookmark bookmark = iterator.next();
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory()) &&
				keep.test(bookmark)) {
				marks.add(bookmark);
			}
		}
		return marks;
	}

	/** Remove the disassembler's ERROR marks that {@code stale} accepts; returns how many. */
	static int remove(Program program, Predicate<Bookmark> stale, TaskMonitor monitor)
			throws CancelledException {
		List<Bookmark> marks = collect(program, stale, monitor);
		BookmarkManager bookmarks = program.getBookmarkManager();
		marks.forEach(bookmarks::removeBookmark);
		return marks.size();
	}

	/**
	 * Remove every ERROR and WARNING bookmark in {@code resolved}, of any category, and return
	 * how many addresses carried one. For code this analysis has itself resolved — a dispatch
	 * stub that is now a thunk — where every such mark describes a decode that no longer
	 * stands: a conflicting decode leaves an ERROR, and an offset-0 stub's literal
	 * {@code JMPF 0000:0000} a WARNING ("flow into non-existing memory").
	 */
	static long clearResolved(Program program, AddressSetView resolved, TaskMonitor monitor)
			throws CancelledException {
		BookmarkManager bookmarks = program.getBookmarkManager();
		long marked = bookmarks.getBookmarkAddresses(BookmarkType.ERROR)
				.union(bookmarks.getBookmarkAddresses(BookmarkType.WARNING))
				.intersect(resolved)
				.getNumAddresses();
		if (marked > 0) {
			bookmarks.removeBookmarks(resolved, BookmarkType.ERROR, monitor);
			bookmarks.removeBookmarks(resolved, BookmarkType.WARNING, monitor);
		}
		return marked;
	}

	/**
	 * Remove the disassembler's ERROR marks at {@code at} once no flow reaches it: a mark there
	 * describes the flow that used to, and one that still does may be described by it.
	 */
	static void removeUnreached(Program program, Address at) {
		if (CodeEvidence.hasFlowReferenceTo(program, at)) {
			return;
		}
		BookmarkManager bookmarks = program.getBookmarkManager();
		for (Bookmark bookmark : bookmarks.getBookmarks(at, BookmarkType.ERROR)) {
			if (Disassembler.ERROR_BOOKMARK_CATEGORY.equals(bookmark.getCategory())) {
				bookmarks.removeBookmark(bookmark);
			}
		}
	}
}
