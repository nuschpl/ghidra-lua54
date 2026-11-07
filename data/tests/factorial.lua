-- Test fixture for the Ghidra Lua 5.4 processor/loader.
-- Exercises: locals, numeric for-loop (FORPREP/FORLOOP), arithmetic (MUL/ADD),
-- comparison + branch (LT/JMP), function calls (CALL), and RETURN1.

local function factorial(n)
    local result = 1
    for i = 2, n do
        result = result * i
    end
    return result
end

local function fib(n)
    if n < 2 then
        return n
    end
    return fib(n - 1) + fib(n - 2)
end

local total = 0
for k = 1, 10 do
    total = total + factorial(k) + fib(k)
end

print("total =", total)
return total
