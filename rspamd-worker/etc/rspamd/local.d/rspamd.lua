-- Heinlein Support SLAC 2024 - Workshop - Sichere Mailcluster mit Rspamd und Spamhaus DQS
-- https://github.com/HeinleinSupport/rspamd-slac-2024
--

-- Include extra lua files from $LOCAL_CONFDIR/local.d/lua.d/*.lua
local local_conf = rspamd_paths['LOCAL_CONFDIR']
local f = io.popen("ls -1 " .. local_conf .. "/local.d/lua.d/*.lua")

if f then
  for mod in f:lines() do
    dofile(mod)
  end
end


-- rspamd_config:register_symbol{
--   type = 'callback', -- or virtual, callback, prefilter or postfilter
--   name = 'SAMPLE_SYMBOL',
--   group = "sample_goup",
--   score = 0.0, -- Metric score
--   flags = 'fine',
--   -- run always: flags = 'empty,explicit_disable,ignore_passthrough,nostat',

--   callback = function(task) -- Main logic
--     local symbol = 'SAMPLE_SYMBOL'
--     rspamd_logger.infox(task, '%s: sample log entry', symbol)
--   end
-- }