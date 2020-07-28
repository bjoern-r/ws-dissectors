----------------------------------------
-- script-name: eap_5g.lua
-- Author: Bjoern Riemer
-- Dissector for EAP-5G Extension protocol.
-- Specified in 3GPP TS 24.502 9.3.2.
--
----------------------------------------

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
local dprint2 = function() end

dprint = function(...)
    print(table.concat({"Lua:", ...}," "))
end
--dprint2 = dprint -- uncomment to see debug messages

----------------------------------------
-- creates a Proto object, but doesn't register it yet
local eap_5g = Proto("eap_5g","EAP-5G")

local eap_ext_vendor_type_ex = Field.new("eap.ext.vendor_type")
local eap_code_ex = Field.new("eap.code")

----------------------------------------
-- multiple ways to do the same thing: create a protocol field (but not register it yet)
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
local msgids = { [1] = "5G-Start", [2] = "5G-NAS message", [4] = "5G-Stop" }

local pf_msg_id          = ProtoField.new("Message-Id", "eap_5g.msg_id", ftypes.UINT8, msgids)
local pf_spare           = ProtoField.new("Spare", "eap_5g.spare", ftypes.UINT8)
local pf_an_param_len    = ProtoField.new("AN-parameter length", "eap_5g.an_param_len", ftypes.UINT16, nil, base.DEC)
local pf_an_parameter    = ProtoField.new("AN-parameter", "eap_5g.an_param", ftypes.STRING)
local pf_naspdu_len      = ProtoField.new("NAS-PDU length", "eap_5g.nas_len", ftypes.UINT16, nil, base.DEC)
local pf_naspdu          = ProtoField.new("NAS-PDU", "eap_5g.nas_pdu", ftypes.STRING)
local pf_extension_data  = ProtoField.new("Extensions", "eap_5g.extension", ftypes.STRING)

local ef_too_short       = ProtoExpert.new("eap_5g.too_short.expert", "message too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_expinfo         = ProtoExpert.new("eap_5g.expert", "Request Details", expert.group.REQUEST_CODE, expert.severity.CHAT)


----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set dns.fields to it, so as to avoid forgetting a field
eap_5g.fields = {pf_msg_id, pf_spare, pf_an_param_len, pf_an_parameter,
                pf_naspdu_len, pf_naspdu, pf_extension_data}
eap_5g.experts = {ef_expinfo, ef_too_short}


----------------------------------------
-- The following creates the callback function for the dissector.
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function eap_5g.dissector(tvbuf,pktinfo,root)
    dprint2("eap_5g.dissector called")

    local eap_ext_vendor_type = eap_ext_vendor_type_ex().value
    if not eap_ext_vendor_type == 3 then
        return 0
    end

    -- set the protocol column to show our protocol name
    --pktinfo.cols.protocol:set("EAP-5G")
    pktinfo.cols.protocol:append("/EAP-5G")

    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents - in this
    -- case (DNS protocol) that's the remainder of the packet.
    local tree = root:add(eap_5g, tvbuf:range(0,pktlen))

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

    local msg_id = tvbuf:range(0,1):uint()
    local rindex = 1
    local eap_code = eap_code_ex().value

    dprint2("eap_code:",eap_code)

    tree:add(pf_msg_id, msg_id)
    tree:add(pf_spare, tvbuf:range(rindex,1))
    rindex = rindex + 1

    --ef_expinfo
    if (msg_id==1) then
        pktinfo.cols.info:append(", 5G-Start")
    end
    if (msg_id==2) then
        local an_len = tvbuf:range(rindex,2):uint()
        if eap_code == 2 then
            -- Response code
            tree:add(pf_an_param_len, tvbuf:range(rindex,2))
            rindex = rindex + 2
            if an_len > 0 then
                Dissector.get("data"):call(tvbuf:range(rindex,an_len):tvb(),pktinfo,tree:add(pf_an_parameter))
                rindex = rindex + an_len
            end
        end
        local nas_len = tvbuf:range(rindex,2):uint()
        tree:add(pf_naspdu_len, tvbuf:range(rindex,2))
        rindex = rindex + 2
        --tree:add(pf_naspdu, tvbuf:range(an_len+6,nas_len))
        Dissector.get("nas-5gs"):call(tvbuf:range(rindex,nas_len):tvb(),pktinfo,tree)
        rindex = rindex + nas_len
    end
    if (msg_id==4) then
        pktinfo.cols.info:append(", 5G-Stop")
    end

    dprint2("bytes left:",pktlen - rindex)

    if pktlen - rindex > 0 then
        tree:add(pf_extension_data, tvbuf:range(rindex,pktlen - rindex))
    end
    return pktlen
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific TCP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("eap.ext.vendor_id"):add(10415, eap_5g)  -- Vendor-Type ID 3 = EAP-5G, defined in TS 24.502 [48], clause 9.2

