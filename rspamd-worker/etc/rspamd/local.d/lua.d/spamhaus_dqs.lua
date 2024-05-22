-- Heinlein Support SLAC 2024 - Workshop - Sichere Mailcluster mit Rspamd und Spamhaus DQS
-- https://github.com/HeinleinSupport/rspamd-slac-2024
--

--[[
Copyright (c) 2023, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

-- require some extra functions
--local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"

local lua_selectors = require "lua_selectors"
local lua_util = require "lua_util"


--[[
These functions are based on the work of Riccardo Alfieri from Spamhaus.
You can find the original code here:

https://github.com/spamhaus/rspamd-dqs

]]--

lua_selectors.register_extractor(rspamd_config, "spamhaus_hbl_cw", {
  get_value = function(task, args) -- mandatory field
    local parts = task:get_text_parts()

    if parts then

      local cw_list = {}

      local cw_re = {}

      cw_re['bch'] = {
          re = rspamd_re.create_cached('(?<!=)bitcoincash:(?:q|p)[a-z0-9]{41}'),
          lowercase = false
      }

      cw_re['xmr'] = {
        re = rspamd_re.create_cached('^(?:4(?:[0-9]|[A-B])(?:.){93})$'),
        lowercase = false
      }

      cw_re['ltc'] = {
        re = rspamd_re.create_cached('^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$'),
        lowercase = false
      }

      cw_re['xrp'] = {
        re = rspamd_re.create_cached('^(?:r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{27,35})$'),
        lowercase = false
      }

      cw_re['eth'] = {
        re = rspamd_re.create_cached('/^0x[a-fA-F0-9]{40}$/i'),
        lowercase = true
      }

      for _, part in ipairs(parts) do

        for _,v in pairs(cw_re) do
          local cw_match = part:filter_words(v.re, 'raw')
          if cw_match then
            for _, m in ipairs(cw_match) do
              if v.lowercase then
                table.insert(cw_list, m:lower())
              else
                table.insert(cw_list, m)
              end
            end
          end
        end
      end
      return cw_list, 'string_list'
    end

    return nil
  end,
  description = 'Return a list of Cryptowallet addresses supported by Spamhaus (next to bitcoin)'
})

local sh_hbl_url_common = rspamd_config:add_hash_map('file:///etc/rspamd/local.d/maps.d/sh_hbl_url_common.map',
  'sh_hbl_url_common.map')
local sh_hbl_url_noslash = rspamd_config:add_hash_map('file:///etc/rspamd/local.d/maps.d/sh_hbl_url_noslash.map',
  'sh_hbl_url_noslash.map')
local sh_hbl_url_withqm = rspamd_config:add_hash_map('file:///etc/rspamd/local.d/maps.d/sh_hbl_url_withqm.map',
  'sh_hbl_url_withqm.map')

lua_selectors.register_extractor(rspamd_config, "spamhaus_hbl_url", {
  get_value = function(task, args) -- mandatory field

    local url_list = {}

    local function find_urls_with_path (url)
      local path = url:get_path();
      if path then
        return true
      end
    end
    local urls = lua_util.extract_specific_urls({
      task = task,
      limit = 10,
      prefix = 'sh_hbl_url',
      filter = find_urls_with_path
    });

    local match = {
       {
        name = "common",
        path_re = '[/?](?:[a-zA-Z0-9()_.=~!/-]|(?:%[0-9a-fA-F][0-9a-fA-F])){2,512}',
        host_map = sh_hbl_url_common,
        lowerhash = false,
      },
      {
        name = "noslash",
        path_re = '[/?](?:[a-zA-Z0-9()_.=~-]|(?:%[0-9a-fA-F][0-9a-fA-F])){2,512}',
        host_map = sh_hbl_url_noslash,
        lowerhash = false,
      },
      {
        name = "withqm",
        path_re = '[/?](?:[a-zA-Z0-9()_.=~/-?]|(?:%[0-9a-fA-F][0-9a-fA-F])){2,512}',
        host_map = sh_hbl_url_withqm,
        lowerhash = false,
      },
      {
        name = "catchall",
        path_re = '^$|^[?].*|^[#].*|[^#?]+',
        lowerhash = true,
      },
    }

    for i,m in pairs(match) do
      if m.path_re then
        match[i]['path_re_o'] = rspamd_re.create_cached(m.path_re)
      end
      if m.host_re then
        match[i]['host_re_o'] = rspamd_re.create_cached(m.host_re)
      end
    end

    for _,u in ipairs(urls) do

      local host = u:get_host():lower()
      local path = u:get_path()

      if host and path then

        for _,m in ipairs(match) do

          if (m.host_map and m.host_map:get_key(host))
            or (m.host_re_o and m.host_re_o:match(host))
            or (not m.host_re and not m.host_map)
            then

            if u:get_query() then
              path = string.format('%s?%s', path, u:get_query())
            end

            if m.lowerhash then
              path = path:lower()
            end

            local path_table = m.path_re_o:search('/'..path)

            if path_table and path_table[1] then
              local port = u:get_port()
              if port and tonumber(port) ~= 0 then
                -- url_list[string.format('%s:%s/%s', host, u:get_port(), path_table[1])] = true
                table.insert(url_list, string.format('%s:%s%s', host, u:get_port(), path_table[1]))
                break
              else
                -- url_list[string.format('%s/%s', host, path_table[1])] = true
                table.insert(url_list, string.format('%s%s', host, path_table[1]))
                break
              end
            end

          end
        end
      end

    end
    return url_list, 'string_list'
  end,
  description = 'Return a list of special urls supported by Spamhaus HBL Url'
})