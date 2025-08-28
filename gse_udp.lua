-- GSE over UDP Dissector (improved)
-- Save as gse_udp.lua in your Wireshark plugins directory

local p_gse = Proto("gseudp", "GSE over UDP")

-- GSE Header fields
local f_start_indicator = ProtoField.bool("gse.start", "Start Indicator", 8, nil, 0x80)
local f_end_indicator   = ProtoField.bool("gse.end",   "End Indicator",   8, nil, 0x40)
local f_label_type = ProtoField.uint8("gse.label_type", "Label Type", base.DEC, {
    [0] = "6 byte label",
    [1] = "3 byte label",
    [2] = "Broadcast",
    [3] = "Re-use"
}, 0x30)
local f_gse_length   = ProtoField.uint16("gse.length",        "GSE Length",   base.DEC, nil, 0x0FFF)
local f_fragment_id  = ProtoField.uint8 ("gse.frag_id",        "Fragment ID",  base.HEX)
local f_total_length = ProtoField.uint16("gse.total_length",   "Total Length", base.DEC)
local f_protocol_type= ProtoField.uint16("gse.protocol",       "Protocol Type", base.HEX, {
    [0x0800] = "IPv4",
    [0x86DD] = "IPv6",
    [0x0806] = "ARP",
    [0x8100] = "VLAN"
})
local f_label_6      = ProtoField.bytes("gse.label6",      "6-byte Label", base.NONE)
local f_label_3      = ProtoField.bytes("gse.label3",      "3-byte Label", base.NONE)
local f_extensions   = ProtoField.bytes("gse.extensions",  "Extensions",   base.NONE)
local f_payload      = ProtoField.bytes("gse.payload",     "Payload",      base.NONE)

-- Error / notes
local f_error        = ProtoField.string("gse.error",      "Error",        base.NONE)
local f_note_pad     = ProtoField.string("gse.note.pad",   "Note",         base.NONE)

p_gse.fields = {
    f_start_indicator, f_end_indicator, f_label_type, f_gse_length,
    f_fragment_id, f_total_length, f_protocol_type,
    f_label_6, f_label_3, f_extensions, f_payload, f_error, f_note_pad
}

-- Protocol type lookup for next dissector
local protocol_dissectors = {
    [0x0800] = "ip",      -- IPv4
    [0x86DD] = "ipv6",    -- IPv6
    [0x0806] = "arp",     -- ARP
}

function p_gse.dissector(buf, pinfo, tree)
    local buf_len = buf:len()
    if buf_len < 2 then return 0 end

    pinfo.cols.protocol = "GSE/UDP"
    local root = tree:add(p_gse, buf(), "Generic Stream Encapsulation")

    -- Allow leading 0x00 padding/alignment before the actual GSE header
    local start_off = 2
    if start_off > 0 then
        root:add(f_note_pad, buf(0, start_off), ("Skipped %d byte(s) of leading padding"):format(start_off))
    end

    if start_off + 2 > buf_len then
        root:add(f_error, buf(), "Truncated: not enough bytes for base header after padding")
        return buf_len
    end

    local offset = start_off

    -- Parse base header (2 bytes)
    local first_byte  = buf(offset, 1):uint()
    local second_byte = buf(offset + 1, 1):uint()

    local start_indicator = bit.band(first_byte, 0x80) ~= 0
    local end_indicator   = bit.band(first_byte, 0x40) ~= 0
    local label_type      = bit.rshift(bit.band(first_byte, 0x30), 4)
    local gse_length      = bit.bor(bit.lshift(bit.band(first_byte, 0x0F), 8), second_byte)

    local hdr = root:add(p_gse, buf(offset, 2 + math.min(gse_length, buf_len - (offset + 2))))
    hdr:add(f_start_indicator, buf(offset, 1), start_indicator)
    hdr:add(f_end_indicator,   buf(offset, 1), end_indicator)
    hdr:add(f_label_type,      buf(offset, 1), label_type)
    hdr:add(f_gse_length,      buf(offset, 2), gse_length)

    offset = offset + 2

    -- Validate length against available bytes
    if gse_length > (buf_len - (offset - start_off)) then
        root:add(f_error, buf(offset, buf_len - offset), ("Invalid GSE length: %d > available %d"):format(
            gse_length, buf_len - (offset - start_off)))
        return buf_len
    end

    -- Fragment header (if any)
    local fragment_id = nil
    if (not start_indicator) and (not end_indicator) then
        -- Continuation fragment: FragID (1 byte)
        if offset + 1 > buf_len then
            root:add(f_error, buf(), "Buffer too short for fragment ID")
            return buf_len
        end
        fragment_id = buf(offset, 1):uint()
        hdr:add(f_fragment_id, buf(offset, 1), fragment_id)
        offset = offset + 1
    elseif start_indicator and (not end_indicator) then
        -- First fragment: FragID (1) + TotalLength (2)
        if offset + 3 > buf_len then
            root:add(f_error, buf(), "Buffer too short for fragmented (first) header")
            return buf_len
        end
        fragment_id = buf(offset, 1):uint()
        local total_length = buf(offset + 1, 2):uint()
        hdr:add(f_fragment_id,  buf(offset, 1), fragment_id)
        hdr:add(f_total_length, buf(offset + 1, 2), total_length)
        offset = offset + 3
    end

    -- Protocol Type & Label only present at start fragments (S=1)
    local protocol_type = nil
    if start_indicator then
        if offset + 2 > buf_len then
            root:add(f_error, buf(), "Buffer too short for protocol type")
            return buf_len
        end
        protocol_type = buf(offset, 2):uint()
        hdr:add(f_protocol_type, buf(offset, 2), protocol_type)
        offset = offset + 2

        -- Label (depending on LT)
        if label_type == 0 then
            -- 6-byte label
            if offset + 6 > buf_len then
                root:add(f_error, buf(), "Buffer too short for 6-byte label")
                return buf_len
            end
            hdr:add(f_label_6, buf(offset, 6))
            offset = offset + 6
        elseif label_type == 1 then
            -- 3-byte label
            if offset + 3 > buf_len then
                root:add(f_error, buf(), "Buffer too short for 3-byte label")
                return buf_len
            end
            hdr:add(f_label_3, buf(offset, 3))
            offset = offset + 3
        else
            -- Broadcast (2) / Re-use (3): no label bytes to consume
        end
    end

    -- (Optional) Extension headers would be parsed here if used; we skip in this minimal dissector

    -- Payload: exactly gse_length minus the header bytes we’ve consumed since the length field
    local header_bytes_after_length = offset - (start_off + 2)
    local payload_length = gse_length - header_bytes_after_length
    if payload_length < 0 then
        root:add(f_error, buf(), "Calculated payload length is negative (check LT/S/E parsing)")
        return buf_len
    end
    if offset + payload_length > buf_len then
        root:add(f_error, buf(), "Payload extends beyond buffer")
        return buf_len
    end

    if payload_length > 0 then
        local payload_buf = buf(offset, payload_length)
        hdr:add(f_payload, payload_buf)

        -- If complete (S=1,E=1) and we know the inner protocol, hand off
        if protocol_type and start_indicator and end_indicator then
            local next_name = protocol_dissectors[protocol_type]
            if next_name then
                local next = Dissector.get(next_name)
                if next then
                    next:call(payload_buf:tvb(), pinfo, tree)
                end
            end
        end
    end

    -- Info column
    local info = "GSE"
    if start_indicator and end_indicator then
        info = info .. " [Complete]"
    elseif start_indicator then
        info = info .. " [First Fragment]"
    elseif end_indicator then
        info = info .. " [Last Fragment]"
    else
        info = info .. " [Fragment]"
    end
    if fragment_id then info = info .. " ID=" .. fragment_id end
    if protocol_type then info = info .. string.format(" Proto=0x%04x", protocol_type) end
    pinfo.cols.info = info

    return buf_len
end

-- Register for your UDP port (change as needed)
local udp_table = DissectorTable.get("udp.port")
udp_table:add(5000, p_gse)
