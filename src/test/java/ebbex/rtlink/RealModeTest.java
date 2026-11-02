package ebbex.rtlink;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;

import generic.test.AbstractGenericTest;

/**
 * Base for tests on {@link RealMode} programs: every program a test opens is disposed after
 * it, including one whose set-up failed half way.
 */
public abstract class RealModeTest extends AbstractGenericTest {

	private final List<RealMode> opened = new ArrayList<>();

	/** A new, empty real-mode program, disposed after the test. */
	protected RealMode realMode(String name) throws Exception {
		var program = new RealMode(name);
		opened.add(program);
		return program;
	}

	@After
	public final void disposePrograms() {
		opened.forEach(RealMode::dispose);
		opened.clear();
	}
}
