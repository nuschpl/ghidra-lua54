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
 * One entry of a Lua 5.4 prototype's constant table (K[]).
 *
 * <p>Constant type tags (from lobject.h, {@code makevariant}):
 * <ul>
 *   <li>0x00 nil</li>
 *   <li>0x01 false</li>
 *   <li>0x11 true</li>
 *   <li>0x03 integer (lua_Integer, 8 bytes LE)</li>
 *   <li>0x13 float   (lua_Number, 8 bytes LE double)</li>
 *   <li>0x04 short string</li>
 *   <li>0x14 long string</li>
 * </ul>
 */
public class LuaConstant {

	public static final int TAG_NIL = 0x00;
	public static final int TAG_FALSE = 0x01;
	public static final int TAG_TRUE = 0x11;
	public static final int TAG_INT = 0x03;
	public static final int TAG_FLOAT = 0x13;
	public static final int TAG_SHRSTR = 0x04;
	public static final int TAG_LNGSTR = 0x14;

	private final int tag;
	private final long intValue;
	private final double floatValue;
	private final String stringValue;

	private LuaConstant(int tag, long intValue, double floatValue, String stringValue) {
		this.tag = tag;
		this.intValue = intValue;
		this.floatValue = floatValue;
		this.stringValue = stringValue;
	}

	public static LuaConstant ofNil() {
		return new LuaConstant(TAG_NIL, 0, 0, null);
	}

	public static LuaConstant ofBoolean(boolean value) {
		return new LuaConstant(value ? TAG_TRUE : TAG_FALSE, value ? 1 : 0, 0, null);
	}

	public static LuaConstant ofInteger(long value) {
		return new LuaConstant(TAG_INT, value, 0, null);
	}

	public static LuaConstant ofFloat(double value) {
		return new LuaConstant(TAG_FLOAT, 0, value, null);
	}

	public static LuaConstant ofString(int tag, String value) {
		return new LuaConstant(tag, 0, 0, value);
	}

	public int getTag() {
		return tag;
	}

	public long getIntValue() {
		return intValue;
	}

	public double getFloatValue() {
		return floatValue;
	}

	public String getStringValue() {
		return stringValue;
	}

	public boolean isString() {
		return tag == TAG_SHRSTR || tag == TAG_LNGSTR;
	}

	/**
	 * @return a short, human-readable rendering suitable for a listing comment
	 */
	public String display() {
		switch (tag) {
			case TAG_NIL:
				return "nil";
			case TAG_FALSE:
				return "false";
			case TAG_TRUE:
				return "true";
			case TAG_INT:
				return Long.toString(intValue);
			case TAG_FLOAT:
				return Double.toString(floatValue);
			case TAG_SHRSTR:
			case TAG_LNGSTR:
				return quote(stringValue);
			default:
				return "?";
		}
	}

	private static String quote(String s) {
		if (s == null) {
			return "<null>";
		}
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length() && i < 60; i++) {
			char ch = s.charAt(i);
			if (ch == '"' || ch == '\\') {
				sb.append('\\').append(ch);
			}
			else if (ch == '\n') {
				sb.append("\\n");
			}
			else if (ch == '\t') {
				sb.append("\\t");
			}
			else if (ch >= 0x20 && ch < 0x7f) {
				sb.append(ch);
			}
			else {
				sb.append(String.format("\\x%02x", (int) ch & 0xff));
			}
		}
		if (s.length() > 60) {
			sb.append("...");
		}
		sb.append('"');
		return sb.toString();
	}

	@Override
	public String toString() {
		return display();
	}
}
