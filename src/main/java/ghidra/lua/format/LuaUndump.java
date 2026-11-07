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
package ghidra.lua.format;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * Parser for Lua 5.4 precompiled chunks (the {@code luac} / {@code lundump} format).
 *
 * <p>Faithful to lundump.c from the Lua 5.4.7 reference source. Header:
 * <pre>
 *   1B 4C 75 61            signature "\x1bLua"
 *   54                     version  (LUAC_VERSION = (5*16)+4)
 *   00                     format   (LUAC_FORMAT)
 *   19 93 0D 0A 1A 0A      LUAC_DATA
 *   04                     sizeof(Instruction)
 *   08                     sizeof(lua_Integer)
 *   08                     sizeof(lua_Number)
 *   78 56 ... (8 bytes)    LUAC_INT  = 0x5678   (endianness check)
 *   ... (8 bytes)          LUAC_NUM  = 370.5    (float format check)
 *   NN                     number of upvalues of the main closure
 *   &lt;main function&gt;        recursively dumped prototype
 * </pre>
 *
 * Integers/sizes are stored with {@code loadUnsigned}: base-128, most-significant group
 * first, and the final byte has its high bit set.
 */
public class LuaUndump {

	public static final byte[] SIGNATURE = { 0x1b, 'L', 'u', 'a' };
	public static final int LUAC_VERSION = 0x54;
	public static final int LUAC_FORMAT = 0x00;
	public static final byte[] LUAC_DATA = { 0x19, (byte) 0x93, 0x0d, 0x0a, 0x1a, 0x0a };
	public static final int INSTRUCTION_SIZE = 4;
	public static final int LUA_INTEGER_SIZE = 8;
	public static final int LUA_NUMBER_SIZE = 8;
	public static final long LUAC_INT = 0x5678L;
	public static final double LUAC_NUM = 370.5;

	/** Maximum prototype nesting depth accepted (cf. LUAI_MAXCCALLS in the Lua source). */
	private static final int MAX_PROTO_DEPTH = 200;

	private final BinaryReader reader;
	private final long fileLength;
	private int mainUpvalueCount;
	private LuaFunctionProto topProto;

	/** False when the chunk omits the LUAC_INT/LUAC_NUM numeric checks (size-optimized variant). */
	private boolean numericChecksPresent = true;
	/** The sentinel byte that replaces the numeric block in the variant, or -1 if standard. */
	private int sentinelByte = -1;

	public LuaUndump(ByteProvider provider) throws IOException {
		this.reader = new BinaryReader(provider, true /* little-endian */);
		this.fileLength = provider.length();
	}

	/**
	 * Quick, allocation-light check that {@code provider} begins with a Lua 5.4 chunk.
	 */
	public static boolean isLuaBytecode(ByteProvider provider) throws IOException {
		if (provider.length() < 4 + 1 + 1 + LUAC_DATA.length + 3 + 16) {
			return false;
		}
		BinaryReader r = new BinaryReader(provider, true);
		byte[] sig = r.readNextByteArray(SIGNATURE.length);
		for (int i = 0; i < SIGNATURE.length; i++) {
			if (sig[i] != SIGNATURE[i]) {
				return false;
			}
		}
		int version = r.readNextUnsignedByte();
		if (version != LUAC_VERSION) {
			return false;
		}
		int format = r.readNextUnsignedByte();
		if (format != LUAC_FORMAT) {
			return false;
		}
		byte[] data = r.readNextByteArray(LUAC_DATA.length);
		for (int i = 0; i < LUAC_DATA.length; i++) {
			if (data[i] != LUAC_DATA[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Parse the whole chunk, validating the header and recursively loading the main
	 * prototype tree.
	 *
	 * @return the top-level (main) prototype
	 * @throws IOException if the stream is truncated or the header is invalid
	 */
	public LuaFunctionProto parse() throws IOException {
		checkHeader();
		mainUpvalueCount = readByte();
		topProto = new LuaFunctionProto();
		loadFunction(topProto, null, 0);
		return topProto;
	}

	public LuaFunctionProto getTopProto() {
		return topProto;
	}

	public int getMainUpvalueCount() {
		return mainUpvalueCount;
	}

	/** @return true for a standard chunk, false for the no-numeric-checks variant. */
	public boolean hasNumericChecks() {
		return numericChecksPresent;
	}

	/** @return the variant's sentinel byte (replacing LUAC_INT/LUAC_NUM), or -1 if standard. */
	public int getSentinelByte() {
		return sentinelByte;
	}

	private void checkHeader() throws IOException {
		byte[] sig = reader.readNextByteArray(SIGNATURE.length);
		for (int i = 0; i < SIGNATURE.length; i++) {
			if (sig[i] != SIGNATURE[i]) {
				throw new IOException("Not a Lua binary chunk (bad signature)");
			}
		}
		int version = readByte();
		if (version != LUAC_VERSION) {
			throw new IOException(String.format(
				"Lua bytecode version mismatch: expected 0x54 (5.4), found 0x%02x", version));
		}
		int format = readByte();
		if (format != LUAC_FORMAT) {
			throw new IOException("Lua bytecode format mismatch: expected 0, found " + format);
		}
		byte[] data = reader.readNextByteArray(LUAC_DATA.length);
		for (int i = 0; i < LUAC_DATA.length; i++) {
			if (data[i] != LUAC_DATA[i]) {
				throw new IOException("Corrupted chunk (LUAC_DATA mismatch)");
			}
		}
		int instrSize = readByte();
		if (instrSize != INSTRUCTION_SIZE) {
			throw new IOException("Unexpected Instruction size: " + instrSize + " (expected 4)");
		}
		int intSize = readByte();
		if (intSize != LUA_INTEGER_SIZE) {
			throw new IOException("Unexpected lua_Integer size: " + intSize + " (expected 8)");
		}
		int numSize = readByte();
		if (numSize != LUA_NUMBER_SIZE) {
			throw new IOException("Unexpected lua_Number size: " + numSize + " (expected 8)");
		}
		// Standard 5.4 chunks store LUAC_INT (lua_Integer 0x5678) and LUAC_NUM
		// (lua_Number 370.5) here as endianness / float-format checks. Some size-optimized
		// builds omit both: observed in lua-eco / OpenWrt MT798x (musl, aarch64) chunks
		// compiled with Lua 5.4.7, where a single sentinel byte appears after the size
		// fields in place of the 16-byte numeric block, immediately before the main
		// closure's upvalue count. Auto-detect by peeking for LUAC_INT; if it is not there,
		// treat the chunk as the no-numeric-checks variant.
		long afterSizes = reader.getPointerIndex();
		if (reader.length() - afterSizes >= 8 && reader.readNextLong() == LUAC_INT) {
			double luacNum = Double.longBitsToDouble(reader.readNextLong());
			if (luacNum != LUAC_NUM) {
				throw new IOException("Float format check failed: expected 370.5, found " + luacNum);
			}
			numericChecksPresent = true;
		}
		else {
			// Variant: no LUAC_INT / LUAC_NUM. Rewind and consume the one-byte sentinel
			// that precedes the upvalue count in these chunks.
			reader.setPointerIndex(afterSizes);
			sentinelByte = readByte();
			numericChecksPresent = false;
		}
	}

	private void loadFunction(LuaFunctionProto f, String parentSource, int depth)
			throws IOException {
		if (depth > MAX_PROTO_DEPTH) {
			throw new IOException(
				"Lua prototype nesting too deep (> " + MAX_PROTO_DEPTH + "); refusing to parse");
		}
		String source = loadStringN();
		f.setSource(source != null ? source : parentSource);
		f.setLineDefined(loadInt());
		f.setLastLineDefined(loadInt());
		f.setNumParams(readByte());
		f.setIsVararg(readByte());
		f.setMaxStackSize(readByte());
		loadCode(f);
		loadConstants(f);
		loadUpvalues(f);
		loadProtos(f, depth);
		loadDebug(f);
	}

	private void loadCode(LuaFunctionProto f) throws IOException {
		int n = loadInt();
		checkCount(n, 4, "code");
		int[] code = new int[n];
		for (int i = 0; i < n; i++) {
			code[i] = reader.readNextInt();
		}
		f.setCode(code);
	}

	private void loadConstants(LuaFunctionProto f) throws IOException {
		int n = loadInt();
		checkCount(n, 1, "constants"); // each constant occupies at least one tag byte
		for (int i = 0; i < n; i++) {
			int tag = readByte();
			switch (tag) {
				case LuaConstant.TAG_NIL:
					f.getConstants().add(LuaConstant.ofNil());
					break;
				case LuaConstant.TAG_FALSE:
					f.getConstants().add(LuaConstant.ofBoolean(false));
					break;
				case LuaConstant.TAG_TRUE:
					f.getConstants().add(LuaConstant.ofBoolean(true));
					break;
				case LuaConstant.TAG_INT:
					f.getConstants().add(LuaConstant.ofInteger(reader.readNextLong()));
					break;
				case LuaConstant.TAG_FLOAT:
					f.getConstants()
							.add(LuaConstant.ofFloat(Double.longBitsToDouble(reader.readNextLong())));
					break;
				case LuaConstant.TAG_SHRSTR:
				case LuaConstant.TAG_LNGSTR:
					f.getConstants().add(LuaConstant.ofString(tag, loadString()));
					break;
				default:
					throw new IOException("Unknown constant tag 0x" + Integer.toHexString(tag));
			}
		}
	}

	private void loadUpvalues(LuaFunctionProto f) throws IOException {
		int n = loadInt();
		checkCount(n, 3, "upvalues"); // 3 bytes each: instack, idx, kind
		for (int i = 0; i < n; i++) {
			int instack = readByte();
			int idx = readByte();
			int kind = readByte();
			f.getUpvalues().add(new LuaUpvalue(instack, idx, kind));
		}
	}

	private void loadProtos(LuaFunctionProto f, int depth) throws IOException {
		int n = loadInt();
		checkCount(n, 1, "protos"); // each nested prototype consumes at least one byte
		for (int i = 0; i < n; i++) {
			LuaFunctionProto child = new LuaFunctionProto();
			loadFunction(child, f.getSource(), depth + 1);
			f.getProtos().add(child);
		}
	}

	private void loadDebug(LuaFunctionProto f) throws IOException {
		// line info (one signed byte per instruction)
		int n = loadInt();
		checkCount(n, 1, "lineinfo");
		for (int i = 0; i < n; i++) {
			reader.readNextByte();
		}
		// absolute line info
		n = loadInt();
		checkCount(n, 2, "abslineinfo"); // at least two bytes (two varint fields) each
		for (int i = 0; i < n; i++) {
			loadInt(); // pc
			loadInt(); // line
		}
		// local variables
		n = loadInt();
		checkCount(n, 1, "locvars");
		for (int i = 0; i < n; i++) {
			String name = loadStringN();
			int startpc = loadInt();
			int endpc = loadInt();
			f.getLocalVars().add(new LuaLocalVar(name, startpc, endpc));
		}
		// upvalue names
		n = loadInt();
		if (n != 0) {
			n = f.getUpvalues().size();
		}
		for (int i = 0; i < n; i++) {
			String name = loadStringN();
			if (i < f.getUpvalues().size()) {
				f.getUpvalues().get(i).setName(name);
			}
		}
	}

	// --- primitive readers -------------------------------------------------------

	private int readByte() throws IOException {
		return reader.readNextUnsignedByte();
	}

	/** Bytes left in the input from the current read position. */
	private long remaining() {
		return fileLength - reader.getPointerIndex();
	}

	/**
	 * Reject an element count that is negative or larger than the input could possibly
	 * hold ({@code n * minElementBytes} bytes), before any allocation. This bounds memory
	 * use when parsing a hostile/corrupt chunk (a {@code .luac} is untrusted input).
	 */
	private void checkCount(int n, long minElementBytes, String what) throws IOException {
		if (n < 0) {
			throw new IOException("Negative " + what + " count: " + n);
		}
		long need = (long) n * minElementBytes;
		if (need > remaining()) {
			throw new IOException("Implausible " + what + " count " + n + " (needs >= " + need +
				" bytes, only " + remaining() + " remain)");
		}
	}

	/**
	 * {@code loadUnsigned} from lundump.c: base-128, MSB group first, terminator byte
	 * has the high bit set. Mirrors the C overflow check so a crafted varint cannot wrap.
	 */
	private long loadUnsigned() throws IOException {
		long x = 0;
		int b;
		do {
			b = readByte();
			if (x > (Long.MAX_VALUE >> 7)) {
				throw new IOException("Integer overflow in Lua chunk (varint too large)");
			}
			x = (x << 7) | (b & 0x7f);
		}
		while ((b & 0x80) == 0);
		return x;
	}

	private int loadInt() throws IOException {
		long x = loadUnsigned();
		if (x < 0 || x > Integer.MAX_VALUE) {
			throw new IOException("Integer value out of range in Lua chunk: " + x);
		}
		return (int) x;
	}

	/** Nullable string: size 0 means "no string"; otherwise the length is size-1. */
	private String loadStringN() throws IOException {
		long size = loadUnsigned();
		if (size == 0) {
			return null;
		}
		long len = size - 1;
		if (len < 0 || len > remaining()) {
			throw new IOException("Implausible Lua string length " + len + " (only " +
				remaining() + " bytes remain)");
		}
		byte[] bytes = reader.readNextByteArray((int) len);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/** Non-nullable string. */
	private String loadString() throws IOException {
		String s = loadStringN();
		if (s == null) {
			throw new IOException("Bad format for constant string (null)");
		}
		return s;
	}
}
