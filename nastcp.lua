----------------------------------------
-- script-name: nastcp.lua
-- Author: Bjoern Riemer
-- Simple plugin to allow the dissection of NAS-5G inside of TCP.
--
----------------------------------------
local default_settings =
{
    port         = 20000,
}

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------
local dprint = function() end

dprint = function(...)
    print(table.concat({"Lua:", ...}," "))
end

----------------------------------------
-- creates a Proto object, but doesn't register it yet
local nastcp = Proto("nastcp","NAS via TCP")

----------------------------------------
-- multiple ways to do the same thing: create a protocol field (but not register it yet)
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
local pf_payload_data       = ProtoField.new("Payload", "nastcp.data", ftypes.STRING)

local ef_expinfo         = ProtoExpert.new("nastcp.expert", "Request Details", expert.group.REQUEST_CODE, expert.severity.CHAT)
local ef_too_short       = ProtoExpert.new("nastcp.too_short.expert", "message too short", expert.group.MALFORMED, expert.severity.ERROR)

----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set dns.fields to it, so as to avoid forgetting a field
nastcp.fields  = {pf_payload_data}
nastcp.experts = {ef_expinfo, ef_too_short}


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.

nastcp.prefs.port  = Pref.uint("Port number", default_settings.port,
                            "The TCP port used by n3iwf NAS (default 20000)")

----------------------------------------
-- a function for handling prefs being changed
function nastcp.prefs_changed()

    if default_settings.port ~= nastcp.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.port, nastcp)
        end
        -- set our new default
        default_settings.port = nastcp.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.port, nastcp)
        end
    end

end


----------------------------------------
-- The following creates the callback function for the dissector.
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function nastcp.dissector(tvbuf,pktinfo,root)

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("NASTCP")

    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (DNS protocol) that's the remainder of the packet.
    local tree = root:add(nastcp, tvbuf:range(0,pktlen))

    -- now let's check it's not too short
    if pktlen < 2 then
        -- since we're going to add this protocol to a specific TCP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        -- the old way: tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet too short")
        -- the correct way now:
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length",pktlen,"too short")
        return
    end

    pktinfo.cols.info:set("(NAStcp Data)")
    -- invoke subdissector
    Dissector.get("nas-5gs"):call(tvbuf,pktinfo,tree)

    -- tell wireshark how much of tvbuff we dissected
    --return pktlen
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific TCP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("tcp.port"):add(default_settings.port, nastcp)

