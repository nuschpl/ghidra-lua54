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

import java.util.ArrayList;
import java.util.List;

/**
 * A Lua 5.4 function prototype ({@code Proto} in lobject.h), as recovered from a
 * precompiled chunk by {@link LuaUndump}.
 *
 * <p>Fields mirror {@code loadFunction()} in lundump.c. {@code code} holds one 32-bit
 * instruction word per entry (little-endian decoded).
 */
public class LuaFunctionProto {

	private String source;
	private int lineDefined;
	private int lastLineDefined;
	private int numParams;
	private int isVararg;
	private int maxStackSize;

	private int[] code = new int[0];
	private final List<LuaConstant> constants = new ArrayList<>();
	private final List<LuaUpvalue> upvalues = new ArrayList<>();
	private final List<LuaFunctionProto> protos = new ArrayList<>();
	private final List<LuaLocalVar> localVars = new ArrayList<>();

	// Assigned during program layout: byte address of this prototype's first instruction.
	private long codeAddress;

	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}

	public int getLineDefined() {
		return lineDefined;
	}

	public void setLineDefined(int lineDefined) {
		this.lineDefined = lineDefined;
	}

	public int getLastLineDefined() {
		return lastLineDefined;
	}

	public void setLastLineDefined(int lastLineDefined) {
		this.lastLineDefined = lastLineDefined;
	}

	public int getNumParams() {
		return numParams;
	}

	public void setNumParams(int numParams) {
		this.numParams = numParams;
	}

	public int getIsVararg() {
		return isVararg;
	}

	public void setIsVararg(int isVararg) {
		this.isVararg = isVararg;
	}

	public int getMaxStackSize() {
		return maxStackSize;
	}

	public void setMaxStackSize(int maxStackSize) {
		this.maxStackSize = maxStackSize;
	}

	public int[] getCode() {
		return code;
	}

	public void setCode(int[] code) {
		this.code = code;
	}

	public List<LuaConstant> getConstants() {
		return constants;
	}

	public List<LuaUpvalue> getUpvalues() {
		return upvalues;
	}

	public List<LuaFunctionProto> getProtos() {
		return protos;
	}

	public List<LuaLocalVar> getLocalVars() {
		return localVars;
	}

	public long getCodeAddress() {
		return codeAddress;
	}

	public void setCodeAddress(long codeAddress) {
		this.codeAddress = codeAddress;
	}

	/** @return total number of bytes occupied by this prototype's code (4 per instruction) */
	public int getCodeByteLength() {
		return code.length * 4;
	}

	/**
	 * Build a readable, unique-ish name for this prototype based on its debug source and
	 * line range, e.g. {@code lua_main} or {@code lua_func_L12}.
	 */
	public String buildName(boolean isTop) {
		if (isTop) {
			return "lua_main";
		}
		return "lua_func_L" + lineDefined;
	}
}
