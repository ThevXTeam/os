-- Login script using salted SHA-256 hashes
local sha = require("sha256")

local usersFile = "/vx/os/users.lua"

local function fileExists(path)
  local f = io.open(path, "r")
  if f then f:close(); return true end
  return false
end

local function writeUsers(users)
  local f = io.open(usersFile, "w")
  if not f then error("Failed to open users file for writing") end
  f:write("return {")
  for user, v in pairs(users) do
    f:write(string.format("['%s'] = { salt = '%s', hash = '%s' },", user, v.salt, v.hash))
  end
  f:write("}\n")
  f:close()
end

local function loadUsers()
  if not fileExists(usersFile) then return nil end
  return dofile(usersFile)
end

local function genSalt()
  local t = tostring(os.time()) .. tostring(math.random(0, 2^31-1))
  return sha.sha256(t):sub(1,16)
end

local function createAdmin()
  print("No users found. Create an admin account.")
  write("Admin username (default 'admin'): ")
  local username = read()
  if username == "" or not username then username = "admin" end
  while true do
    write("Password: ")
    local p1 = read("*")
    write("Confirm: ")
    local p2 = read("*")
    if p1 == p2 and p1 ~= "" then
      local salt = genSalt()
      local h = sha.sha256(salt .. p1)
      local users = {}
      users[username] = { salt = salt, hash = h }
      writeUsers(users)
      print("Admin user created.")
      return users
    else
      print("Passwords did not match or were empty. Try again.")
    end
  end
end

local function isAuthorized(users, username, password)
  local entry = users[username]
  if not entry then return false end
  local h = sha.sha256(entry.salt .. password)
  return h == entry.hash
end

local function login()
  math.randomseed(os.time())
  local users = loadUsers()
  if not users then users = createAdmin() end


  while true do
    print("                      Username:")
    local username = read()
    print("                      Password:")
    local password = read("*")
    if isAuthorized(users, username, password) then
      print("                 Login successful!")
      break
    else
      print("Invalid username or password. Please try again.")
    end
  end
end

login()
