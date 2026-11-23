package com.lauriewired.ghidramcp.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Supplies the program that backend requests operate on, and the execution-mode specific
 * pieces (GUI location, where writes must run).
 */
public interface ProgramProvider {

	/** Capability: the user's current location in the GUI is available. */
	String CAP_GUI_CONTEXT = "gui_context";

	/** @return the target program, or null if none is open */
	Program getProgram();

	/**
	 * @return every program that can be targeted, the active one first. The default exposes just
	 *         the single program of {@link #getProgram()}.
	 */
	default List<Program> getOpenPrograms() {
		Program program = getProgram();
		return program == null ? List.of() : List.of(program);
	}

	/** Makes the given program the active one in the GUI. */
	default void showProgram(Program program) {
		throw McpException.unsupported("Switching the active program is not available in " + mode() + " mode");
	}

	/** Stable identifier of a program: its project path, or its name if it was never saved. */
	static String programId(Program program) {
		return program.getDomainFile() != null ? program.getDomainFile().getPathname()
				: program.getName();
	}

	/**
	 * Finds an open program by id (project path) or, if that is unambiguous, by name. Matching is
	 * case-insensitive.
	 */
	default Program resolveProgram(String selector) {
		List<Program> open = getOpenPrograms();
		if (open.isEmpty()) {
			throw McpException.noProgram();
		}
		for (Program p : open) {
			if (programId(p).equalsIgnoreCase(selector)) {
				return p;
			}
		}
		List<Program> byName = new ArrayList<>();
		for (Program p : open) {
			if (p.getName().equalsIgnoreCase(selector)) {
				byName.add(p);
			}
		}
		if (byName.size() == 1) {
			return byName.get(0);
		}
		if (byName.size() > 1) {
			throw McpException.ambiguous("'" + selector + "' matches " + byName.size() +
				" open programs; use one of the ids from list_programs: " + ids(byName));
		}
		throw McpException.notFound("No open program matches '" + selector + "'. Open programs: " +
			ids(open));
	}

	private static String ids(List<Program> programs) {
		return String.join(", ", programs.stream().map(ProgramProvider::programId).toList());
	}

	/** @return "gui" or "headless" */
	String mode();

	Set<String> capabilities();

	default Address getCurrentAddress() {
		throw McpException.unsupported("The current GUI location is not available in " + mode() + " mode");
	}

	/** @return a data type service for type lookups, or null if none is available */
	default DataTypeQueryService getDataTypeService() {
		return null;
	}

	/**
	 * Runs a program-modifying action on the thread that writes must use, and returns its result.
	 * Runtime exceptions thrown by the action propagate to the caller.
	 */
	<T> T runWrite(Supplier<T> action);
}
