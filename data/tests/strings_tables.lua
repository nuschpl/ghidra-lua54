-- Test fixture for the Ghidra Lua 5.4 processor/loader.
-- Exercises: table constructor (NEWTABLE/SETLIST/SETFIELD), string constants (LOADK),
-- GETFIELD/SETFIELD, GETTABUP (globals via _ENV upvalue), CONCAT, generic for
-- (TFORPREP/TFORCALL/TFORLOOP), and the length operator (LEN).

local t = { 10, 20, 30, name = "widget", kind = "demo" }

local function describe(tbl)
    local out = tbl.name .. ":" .. tbl.kind
    local sum = 0
    for _, v in ipairs(tbl) do
        sum = sum + v
    end
    return out, sum, #tbl
end

local label, sum, count = describe(t)
print(label, sum, count)
return label
