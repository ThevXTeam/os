-- adduser.lua - add a user to users.lua using salted SHA-256 hashes
local sha = require("sha256")

local usersFile = "vx/os/users.lua"

local function fileExists(path)
  local f = io.open(path, "r")
  if f then f:close(); return true end
  return false
end

local function writeUsers(users)
  local f = io.open(usersFile, "w")
  if not f then error("Failed to open users file for writing") end
  f:write("return {\n")
  for user, v in pairs(users) do
    f:write(string.format("['%s'] = { salt = '%s', hash = '%s' },\n", user, v.salt, v.hash))
  end
  f:write("}\n")
  f:close()
end

local function loadUsers()
  if not fileExists(usersFile) then return {} end
  return dofile(usersFile) or {}
end

local function genSalt()
  math.randomseed(os.time())
  local t = tostring(os.time()) .. tostring(math.random(0, 2^31-1))
  return sha.sha256(t):sub(1,16)
end

local function addUser()
  local users = loadUsers()
  write("New username: ")
  local username = read()
  if not username or username == "" then print("Username cannot be empty"); return end
  if users[username] then print("User already exists"); return end
  while true do
    write("Password: ")
    local p1 = read("*")
    write("Confirm: ")
    local p2 = read("*")
    if p1 == p2 and p1 ~= "" then
      local salt = genSalt()
      local h = sha.sha256(salt .. p1)
      users[username] = { salt = salt, hash = h }
      writeUsers(users)
      print("User added: " .. username)
      return
    else
      print("Passwords did not match or were empty. Try again.")
    end
  end
end

addUser()
