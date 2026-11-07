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
 * A local-variable debug record of a Lua 5.4 prototype ({@code LocVar} in lobject.h).
 * {@code startpc}/{@code endpc} are instruction indices delimiting the variable's scope.
 */
public class LuaLocalVar {

	private final String name;
	private final int startPc;
	private final int endPc;

	public LuaLocalVar(String name, int startPc, int endPc) {
		this.name = name;
		this.startPc = startPc;
		this.endPc = endPc;
	}

	public String getName() {
		return name;
	}

	public int getStartPc() {
		return startPc;
	}

	public int getEndPc() {
		return endPc;
	}
}
