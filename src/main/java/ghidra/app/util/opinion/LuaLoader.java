/*
 * Copyright 2026 nuschpl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.lua.format.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Lua 5.4 precompiled bytecode (the {@code luac} / {@code lundump} format,
 * signature {@code 1B 4C 75 61} with version byte {@code 0x54}).
 *
 * <p>The loader parses the chunk ({@link LuaUndump}), lays every prototype's {@code code[]}
 * contiguously into the {@code ram} space (4 bytes per instruction), creates an entry point
 * and a named label for each prototype, and annotates constant / upvalue / closure references
 * with listing comments. Disassembly and p-code are provided by the {@code Lua:LE:32:default}
 * SLEIGH language.
 */
public class LuaLoader extends AbstractProgramWrapperLoader {

	public static final String LUA_NAME = "Lua 5.4 bytecode (luac)";
	private static final String LANGUAGE_ID = "Lua:LE:32:default";
	private static final String COMPILER_ID = "default";

	/** Base address of the laid-out code image. */
	private static final long CODE_BASE = 0x10000L;

	/** Upper bound on the assembled code image, to reject crafted/corrupt chunks. */
	private static final long MAX_IMAGE_BYTES = 256L * 1024 * 1024;

	// Opcode numbers (from lopcodes.h) used for comment annotation.
	private static final int OP_LOADK = 3;
	private static final int OP_GETUPVAL = 9;
	private static final int OP_SETUPVAL = 10;
	private static final int OP_GETTABUP = 11;
	private static final int OP_GETFIELD = 14;
	private static final int OP_SETTABUP = 15;
	private static final int OP_SETFIELD = 18;
	private static final int OP_SELF = 20;
	private static final int OP_ADDK = 22;
	private static final int OP_BXORK = 31;
	private static final int OP_MMBINK = 48;
	private static final int OP_EQK = 60;
	private static final int OP_CLOSURE = 79;

	@Override
	public String getName() {
		return LUA_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (LuaUndump.isLuaBytecode(provider)) {
			loadSpecs.add(new LoadSpec(this, CODE_BASE,
				new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_ID), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		TaskMonitor monitor = settings.monitor();
		ByteProvider provider = settings.provider();

		LuaFunctionProto top;
		try {
			top = new LuaUndump(provider).parse();
		}
		catch (IOException e) {
			throw new IOException("Failed to parse Lua 5.4 chunk: " + e.getMessage(), e);
		}

		// Flatten the prototype tree (pre-order) and assign contiguous code addresses.
		List<LuaFunctionProto> protos = new ArrayList<>();
		flatten(top, protos);

		long cursor = CODE_BASE;
		for (LuaFunctionProto p : protos) {
			p.setCodeAddress(cursor);
			// All arithmetic in long; leave at least one slot per prototype.
			cursor += Math.max((long) p.getCode().length * 4, 4);
		}
		long imageEnd = cursor;

		long imageLenLong = imageEnd - CODE_BASE;
		if (imageLenLong <= 0 || imageLenLong > MAX_IMAGE_BYTES) {
			throw new IOException("Lua code image size " + imageLenLong +
				" bytes is out of range (cap " + MAX_IMAGE_BYTES + ")");
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		// Assemble the full code image as little-endian instruction words.
		int imageLen = (int) imageLenLong;
		byte[] image = new byte[imageLen];
		for (LuaFunctionProto p : protos) {
			int off = (int) (p.getCodeAddress() - CODE_BASE);
			int[] code = p.getCode();
			for (int i = 0; i < code.length; i++) {
				int w = code[i];
				image[off + i * 4] = (byte) (w & 0xff);
				image[off + i * 4 + 1] = (byte) ((w >> 8) & 0xff);
				image[off + i * 4 + 2] = (byte) ((w >> 16) & 0xff);
				image[off + i * 4 + 3] = (byte) ((w >> 24) & 0xff);
			}
		}

		Address start = space.getAddress(CODE_BASE);
		try {
			Memory memory = program.getMemory();
			MemoryBlock block = memory.createInitializedBlock("code", start,
				new ByteArrayInputStream(image), imageLen, monitor, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
		}
		catch (Exception e) {
			throw new IOException("Failed to create code memory block: " + e.getMessage(), e);
		}

		// Name prototypes, create entry points, and annotate.
		SymbolTable symbolTable = program.getSymbolTable();
		Listing listing = program.getListing();
		Map<LuaFunctionProto, String> names = new IdentityHashMap<>();
		Set<String> used = new HashSet<>();
		for (LuaFunctionProto p : protos) {
			String base = p.buildName(p == top);
			String name = base;
			int suffix = 1;
			while (!used.add(name)) {
				name = base + "_" + (suffix++);
			}
			names.put(p, name);
		}

		for (LuaFunctionProto p : protos) {
			monitor.checkCancelled();
			Address entry = space.getAddress(p.getCodeAddress());
			String name = names.get(p);
			try {
				symbolTable.createLabel(entry, name, SourceType.IMPORTED);
				symbolTable.addExternalEntryPoint(entry);
			}
			catch (Exception e) {
				// Non-fatal: keep going so the rest of the image still loads.
			}
			listing.setComment(entry, CommentType.PLATE, safeComment(buildHeaderComment(p, names)));
			annotateConstants(p, space, listing, names);
		}
	}

	/**
	 * Pre-order flatten of the prototype tree using an explicit stack (no recursion, so a
	 * deeply nested chunk cannot overflow the Java stack here; depth is also bounded by the
	 * parser).
	 */
	private static void flatten(LuaFunctionProto top, List<LuaFunctionProto> out) {
		Deque<LuaFunctionProto> stack = new ArrayDeque<>();
		stack.push(top);
		while (!stack.isEmpty()) {
			LuaFunctionProto p = stack.pop();
			out.add(p);
			List<LuaFunctionProto> kids = p.getProtos();
			for (int i = kids.size() - 1; i >= 0; i--) { // push reversed to keep pre-order
				stack.push(kids.get(i));
			}
		}
	}

	/**
	 * Neutralize Ghidra comment-annotation syntax ({@code &#123;@...&#125;}) in text taken
	 * from the (untrusted) chunk, so a crafted string/name cannot inject a listing
	 * annotation (e.g. a clickable {@code &#123;@url ...&#125;}). Also strips NULs.
	 */
	private static String safeComment(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("\0", "").replace("{@", "{ @");
	}

	/** Max length of any single untrusted string (source / name) placed in a comment. */
	private static final int MAX_TEXT = 120;
	/** Max length of a whole plate comment, as a backstop against amplification. */
	private static final int MAX_COMMENT = 64 * 1024;

	/** Truncate an untrusted string to {@link #MAX_TEXT} chars (null -> "?"). */
	private static String clip(String s) {
		if (s == null) {
			return "?";
		}
		return s.length() <= MAX_TEXT ? s : s.substring(0, MAX_TEXT) + "...";
	}

	private String buildHeaderComment(LuaFunctionProto p, Map<LuaFunctionProto, String> names) {
		StringBuilder sb = new StringBuilder();
		sb.append(names.get(p)).append('\n');
		if (p.getSource() != null) {
			sb.append("source: ").append(clip(p.getSource())).append('\n');
		}
		sb.append("lines: ").append(p.getLineDefined()).append("..").append(p.getLastLineDefined())
				.append('\n');
		sb.append("params: ").append(p.getNumParams());
		sb.append(p.getIsVararg() != 0 ? " (+vararg)" : "").append('\n');
		sb.append("maxstacksize: ").append(p.getMaxStackSize()).append('\n');

		if (!p.getUpvalues().isEmpty()) {
			sb.append("upvalues:\n");
			List<LuaUpvalue> ups = p.getUpvalues();
			for (int i = 0; i < ups.size(); i++) {
				LuaUpvalue u = ups.get(i);
				sb.append("  U[").append(i).append("] ").append(clip(u.getName()))
						.append(u.getInStack() != 0 ? " (in stack)" : " (upvalue)").append('\n');
			}
		}
		if (!p.getConstants().isEmpty()) {
			sb.append("constants:\n");
			List<LuaConstant> ks = p.getConstants();
			for (int i = 0; i < ks.size(); i++) {
				sb.append("  K[").append(i).append("] = ").append(ks.get(i).display()).append('\n');
			}
		}
		if (!p.getLocalVars().isEmpty()) {
			sb.append("locals:\n");
			for (LuaLocalVar lv : p.getLocalVars()) {
				sb.append("  ").append(clip(lv.getName())).append(" [pc ")
						.append(lv.getStartPc()).append("..").append(lv.getEndPc()).append("]\n");
			}
		}
		String out = sb.toString();
		return out.length() <= MAX_COMMENT ? out : out.substring(0, MAX_COMMENT) + "\n...";
	}

	/**
	 * Attach EOL comments at each instruction that references a constant, upvalue, or
	 * nested prototype, resolving the referenced value.
	 */
	private void annotateConstants(LuaFunctionProto p, AddressSpace space, Listing listing,
			Map<LuaFunctionProto, String> names) {
		int[] code = p.getCode();
		List<LuaConstant> ks = p.getConstants();
		List<LuaUpvalue> ups = p.getUpvalues();
		for (int i = 0; i < code.length; i++) {
			int w = code[i];
			int op = w & 0x7f;
			int a = (w >> 7) & 0xff;
			int b = (w >> 16) & 0xff;
			int cc = (w >> 24) & 0xff;
			int k = (w >> 15) & 1;
			int bx = (w >> 15) & 0x1ffff;

			int kIdx = -1;
			int uIdx = -1;
			int pIdx = -1;

			switch (op) {
				case OP_LOADK:
					kIdx = bx;
					break;
				case OP_GETTABUP:
					uIdx = b;
					kIdx = cc;
					break;
				case OP_GETFIELD:
					kIdx = cc;
					break;
				case OP_SETTABUP:
					uIdx = a;
					kIdx = b;
					break;
				case OP_SETFIELD:
					kIdx = b;
					break;
				case OP_SELF:
					if (k == 1) {
						kIdx = cc;
					}
					break;
				case OP_MMBINK:
					kIdx = b;
					break;
				case OP_EQK:
					kIdx = b;
					break;
				case OP_GETUPVAL:
				case OP_SETUPVAL:
					uIdx = b;
					break;
				case OP_CLOSURE:
					pIdx = bx;
					break;
				default:
					if (op >= OP_ADDK && op <= OP_BXORK) { // arithmetic/bitwise K variants
						kIdx = cc;
					}
					break;
			}

			StringBuilder note = new StringBuilder();
			if (kIdx >= 0 && kIdx < ks.size()) {
				note.append("K[").append(kIdx).append("] = ").append(ks.get(kIdx).display());
			}
			if (uIdx >= 0 && uIdx < ups.size()) {
				if (note.length() > 0) {
					note.append("  ");
				}
				LuaUpvalue u = ups.get(uIdx);
				note.append("U[").append(uIdx).append("] = ").append(clip(u.getName()));
			}
			if (pIdx >= 0 && pIdx < p.getProtos().size()) {
				if (note.length() > 0) {
					note.append("  ");
				}
				note.append("closure -> ").append(names.get(p.getProtos().get(pIdx)));
			}

			if (note.length() > 0) {
				Address addr = space.getAddress(p.getCodeAddress() + (long) i * 4);
				listing.setComment(addr, CommentType.EOL, safeComment(note.toString()));
			}
		}
	}
}
