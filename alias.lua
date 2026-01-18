-- create a `pm` alias that delegates to `/vx/pm/init.lua` when available
if fs.exists("/vx/os/adduser.lua") then
  pcall(function() shell.setAlias("adduser", "/vx/os/adduser.lua") end)
end