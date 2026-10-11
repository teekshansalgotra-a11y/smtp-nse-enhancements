local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Lists SMTP extensions advertised through EHLO,
counts them, and reports whether STARTTLS is advertised.
]]

author = "Teekshan Salgotra"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
    {25, 465, 587},
    {"smtp", "smtps", "submission"}
)

action = function(host, port)
    local options = {
        timeout = 10000,
        recv_before = true,
        ssl = (port.number == 465)
    }

    local socket, err = smtp.connect(host, port, options)

    if not socket then
        return "Connection failed: " .. tostring(err)
    end

    local status, response = smtp.ehlo(socket, "nmap.local")
    smtp.quit(socket)

    if not status then
        return "EHLO request failed: " .. tostring(response)
    end

    local extensions = {}
    local seen = {}
    local starttls = false

    
    local first_line = true

    for line in tostring(response or ""):gmatch("[^\r\n]+") do
        local text = line:match("^%s*%d%d%d[- ](.*)$")

        if text then
            text = text:match("^%s*(.-)%s*$") or ""

            if first_line then
                -- The first EHLO response line is the server greeting.
                first_line = false
            else
                -- Each subsequent line advertises an extension.
                local name = text:match("^([%w_-]+)")

                    if name then
                        name = name:upper()

                    if not seen[name] then
                        seen[name] = true
                        table.insert(extensions, name)
                    end

                    if name == "STARTTLS" then
                        starttls = true
                    end
                end
            end
        end
    end


    table.sort(extensions)

    local output = {"Advertised SMTP extensions:"}

    for i, name in ipairs(extensions) do
        table.insert(output, i .. ". " .. name)
    end

    table.insert(output, "")
    table.insert(output, "Total extensions: " .. #extensions)
    table.insert(output,
        "STARTTLS advertised: " .. (starttls and "Yes" or "No"))

    return stdnse.format_output(true, output)
end
   
