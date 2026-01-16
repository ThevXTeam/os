-- Minimal SHA-256 implementation (returns lowercase hex digest)
-- Attempts to use available bit libraries (`bit32`, `bit`) when present.
local M = {}

local bitlib = bit32 or (bit and {
  band = bit.band, bor = bit.bor, bxor = bit.bxor, rshift = bit.rshift, lshift = bit.lshift,
  rol = function(x, n) return bit.lrotate(x, n) end,
  ror = function(x, n) return bit.rrotate(x, n) end,
})

if not bitlib then
  error("sha256.lua requires bit32 or bit library available in this Lua environment")
end

local function rrotate(x, n)
  if bitlib.ror then return bitlib.ror(x, n) end
  return (bitlib.rshift(x, n) + bitlib.lshift(x, 32 - n)) % 2^32
end

local function tohex(n)
  return string.format("%08x", n)
end

local function preproc(msg)
  local l = #msg * 8
  msg = msg .. string.char(0x80)
  while (#msg % 64) ~= 56 do msg = msg .. string.char(0) end
  -- append 64-bit length (big-endian)
  local hi = math.floor(l / 2^32)
  local lo = l % 2^32
  local function pack32(x)
    local b1 = math.floor(x / 16777216) % 256
    local b2 = math.floor(x / 65536) % 256
    local b3 = math.floor(x / 256) % 256
    local b4 = x % 256
    return string.char(b1, b2, b3, b4)
  end
  msg = msg .. pack32(hi) .. pack32(lo)
  return msg
end

local function sha256(msg)
  local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  }

  local H = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}

  msg = preproc(msg)
  local chunks = #msg / 64

  for i = 1, chunks do
    local w = {}
    local chunk = msg:sub((i-1)*64+1, i*64)
    for t = 0, 15 do
      local j = t*4+1
      local a,b,c,d = chunk:byte(j, j+3)
      w[t] = ((a * 256 + b) * 256 + c) * 256 + d
    end
    for t = 16, 63 do
      local s0 = bitlib.bxor(rrotate(w[t-15], 7), rrotate(w[t-15], 18), bitlib.rshift(w[t-15], 3))
      local s1 = bitlib.bxor(rrotate(w[t-2], 17), rrotate(w[t-2], 19), bitlib.rshift(w[t-2], 10))
      w[t] = (w[t-16] + s0 + w[t-7] + s1) % 2^32
    end

    local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]

    for t = 0, 63 do
      local S1 = bitlib.bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
      local ch = bitlib.bxor(bitlib.band(e, f), bitlib.band(bitlib.bnot(e), g))
      local temp1 = (h + S1 + ch + K[t+1] + w[t]) % 2^32
      local S0 = bitlib.bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
      local maj = bitlib.bxor(bitlib.band(a, b), bitlib.band(a, c), bitlib.band(b, c))
      local temp2 = (S0 + maj) % 2^32

      h = g
      g = f
      f = e
      e = (d + temp1) % 2^32
      d = c
      c = b
      b = a
      a = (temp1 + temp2) % 2^32
    end

    H[1] = (H[1] + a) % 2^32
    H[2] = (H[2] + b) % 2^32
    H[3] = (H[3] + c) % 2^32
    H[4] = (H[4] + d) % 2^32
    H[5] = (H[5] + e) % 2^32
    H[6] = (H[6] + f) % 2^32
    H[7] = (H[7] + g) % 2^32
    H[8] = (H[8] + h) % 2^32
  end

  local out = {}
  for i = 1, 8 do out[i] = tohex(H[i]) end
  return table.concat(out)
end

M.sha256 = sha256
return M
