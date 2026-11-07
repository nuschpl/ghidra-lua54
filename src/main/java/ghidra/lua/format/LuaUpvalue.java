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

/**
 * An upvalue descriptor of a Lua 5.4 prototype ({@code Upvaldesc} in lobject.h).
 */
public class LuaUpvalue {

	private final int instack;
	private final int idx;
	private final int kind;
	private String name;

	public LuaUpvalue(int instack, int idx, int kind) {
		this.instack = instack;
		this.idx = idx;
		this.kind = kind;
	}

	/** @return 1 if the upvalue is in the stack (a local of the enclosing function) */
	public int getInStack() {
		return instack;
	}

	/** @return index of upvalue (in the stack or in the enclosing function's upvalue list) */
	public int getIdx() {
		return idx;
	}

	/** @return kind of corresponding variable (regular / const / to-be-closed / compile-time const) */
	public int getKind() {
		return kind;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
