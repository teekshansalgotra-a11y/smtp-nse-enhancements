local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"

description = [[
Analyzes SMTP response codes returned to EHLO and HELP commands.
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

    local socket, response = smtp.connect(host, port, options)

    if not socket then
        return "Connection failed: " .. tostring(response)
    end

    local output = {}

    local function analyze(label, status, reply)
        reply = tostring(reply or "")
        reply = reply:gsub("\r", ""):gsub("\n", " ")
        local code = reply:match("(%d%d%d)")

        if not status then
            table.insert(output, label .. ": Request failed")
            table.insert(output, "Response: " .. reply)
        elseif code then
            table.insert(output, label .. ": Response code " .. code)
            table.insert(output, "Response: " .. reply)
        else
            table.insert(output, label .. ": No numeric code found")
            table.insert(output, "Response: " .. reply)
        end
    end

    local status, reply = smtp.ehlo(socket, "nmap.local")
    analyze("EHLO", status, reply)

    if status then
        local help_status, help_reply = smtp.help(socket)
        analyze("HELP", help_status, help_reply)
    end

    smtp.quit(socket)

    return stdnse.format_output(true, output)
end
