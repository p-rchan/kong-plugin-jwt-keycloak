local url = require "socket.url"
local http = require "socket.http"
local https = require "ssl.https"
local cjson_safe = require "cjson.safe"
local convert = require "kong.plugins.jwt-keycloak.key_conversion"

local function table_to_string(tbl)
    local result = ""
    for k, v in pairs(tbl) do
        -- Check the key type (ignore any numerical keys - assume its an array)
        if type(k) == "string" then
            result = result .. "[\"" .. k .. "\"]" .. "="
        end

        -- Check the value type
        if type(v) == "table" then
            result = result .. table_to_string(v)
        elseif type(v) == "boolean" then
            result = result .. tostring(v)
        else
            result = result .. "\"" .. v .. "\""
        end
        result = result .. ","
    end
    -- Remove leading commas from the result
    if result ~= "" then
        result = result:sub(1, result:len() - 1)
    end
    return result
end

local function isempty(s)
    return s== nuil or s == ''
end

local function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
         end
         return s .. '} '
    else
         return tostring(o)
    end
end


local function get_request(url, scheme, port)
    local req
    if scheme == "https" then
        req = https.request
    else
        req = http.request
    end

    local res
    local status
    local err

    local chunks = {}
    res, status = req{
        url = url,
        port = port,
        sink = ltn12.sink.table(chunks)
    }
    
    if status ~= 200 then
        return nil, 'Failed calling url ' .. url .. ' response status ' .. status
    end

    res, err = cjson_safe.decode(table.concat(chunks))
    if not res then
        return nil, 'Failed to parse json response'
    end
    
    return res, nil
end

local function get_wellknown_endpoint(well_known_template, issuer)
    return string.format(well_known_template, issuer)
end

local function get_issuer_keys(conf,well_known_endpoint)
    -- Get port of the request: This is done because keycloak 3.X.X does not play well with lua socket.http
    local req = url.parse(well_known_endpoint)
    kong.log.debug('get_issuer_keys starting.. well_known_endpoint is:'..well_known_endpoint)
    kong.log.debug('key_url_override is : '.. conf.keyurl_local_override);
  
    local final_well_known_endpoint = well_known_endpoint
    local final_jwks_uri

    if conf.keyurl_local_override then
        final_well_known_endpoint = conf.keyurl_local_override .. '.well-known/openid-configuration'
    end

    kong.log.debug('using wellknownurl: ' .. final_well_known_endpoint)
    local res, err = get_request(well_known_endpoint, req.scheme, req.port)
    if err then
        return nil, err
    end
    kong.log.debug('well_known_endpoint response:'..dump(res))

    final_jwks_uri = res['jwks_uri']

    if conf.keyurl_local_override then
        final_jwks_uri = conf.keyurl_local_override .. '/protocol/openid-connect/certs'
    end
    kong.log.debug('jwks_uri:'..final_jwks_uri)

    local res, err = get_request(final_jwks_uri, req.scheme,  req.port)
    if err then
        return nil, err
    end

    local keys = {}
    for i, key in ipairs(res['keys']) do
        keys[i] = string.gsub(
            convert.convert_kc_key(key), 
            "[\r\n]+", ""
        )
    end
    return keys, nil
end

return {
    get_request = get_request,
    get_issuer_keys = get_issuer_keys,
    get_wellknown_endpoint = get_wellknown_endpoint,
}
