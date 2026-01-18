-- create an `adduser` alias that delegates to `/vx/os/adduser.lua` when available
if fs.exists("/vx/os/adduser.lua") then
  pcall(function() shell.setAlias("adduser", "/vx/os/adduser.lua") end)
else
  print("No adduser script found at /vx/os/adduser.lua")
end