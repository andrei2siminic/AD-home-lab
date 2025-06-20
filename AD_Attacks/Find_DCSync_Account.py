from ldap3 import Server, Connection, NTLM, ALL, BASE
from ldap3.protocol.microsoft import security_descriptor_control
import uuid
import struct
from io import BytesIO

# --- Configuration ---
domain = "offensive.local"
username = "franky.lanie"
password = "Password123"
dc_ip = "192.168.56.2"

# --- DCSync GUIDs ---
REPL_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "Replicating Directory Changes In Filtered Set"
}

resolved_sids = {}

def format_sid(raw_sid):
    if len(raw_sid) < 8:
        return "INVALID_SID"
    revision = raw_sid[0]
    sub_authority_count = raw_sid[1]
    identifier_authority = int.from_bytes(raw_sid[2:8], byteorder='big')
    sid = f"S-{revision}-{identifier_authority}"
    expected_len = 8 + 4 * sub_authority_count
    if len(raw_sid) < expected_len:
        return f"{sid}-MALFORMED"
    for i in range(sub_authority_count):
        sub_auth = struct.unpack('<I', raw_sid[8 + i*4:12 + i*4])[0]
        sid += f"-{sub_auth}"
    return sid

def resolve_sid_to_entry(sid, conn, base_dn):
    if sid in resolved_sids:
        return resolved_sids[sid]
    conn.search(base_dn, f"(objectSid={sid})", attributes=['*'])
    if conn.entries:
        resolved_sids[sid] = conn.entries[0]
        return conn.entries[0]
    return None

def dump_user_info(entry, right_name):
    print(f"\n[!] {right_name} granted to:")
    print("[>] Distinguished Name:", entry.entry_dn)
    for attr in entry.entry_attributes:
        print(f"    {attr}: {entry[attr].value}")

def check_acl_for_dcsync(sd_raw, conn, base_dn):
    stream = BytesIO(sd_raw)

    stream.seek(16)
    dacl_offset = struct.unpack("<I", stream.read(4))[0]
    print(f"[DEBUG] DACL offset: {dacl_offset}")
    print(f"[DEBUG] Descriptor length: {len(sd_raw)}")
    print(f"[DEBUG] Raw SD: {sd_raw[:64].hex()}")

    if dacl_offset == 0 or dacl_offset >= len(sd_raw):
        print("[!] No valid DACL present.\n")
        return

    stream.seek(dacl_offset)

    try:
        acl_start = stream.tell()
        acl_size = struct.unpack("<H", stream.read(2))[0]
        ace_count = struct.unpack("<H", stream.read(2))[0]
        stream.seek(4, 1)  # skip ACL revision/reserved
        acl_end = acl_start + acl_size

        if ace_count > 2000:
            print(f"[!] ACE count too large ({ace_count}) — skipping for safety.\n")
            return

        print(f"[*] DACL has {ace_count} ACEs\n")
    except struct.error as e:
        print(f"[!] Failed to read ACL header: {e}\n")
        return

    for ace_index in range(ace_count):
        ace_pos = stream.tell()
        try:
            if len(sd_raw) - ace_pos < 8:
                print(f"[!] Skipping ACE #{ace_index}: Not enough data for ACE header")
                break

            ace_type = struct.unpack("B", stream.read(1))[0]
            ace_flags = struct.unpack("B", stream.read(1))[0]
            ace_size = struct.unpack("<H", stream.read(2))[0]
            access_mask = struct.unpack("<I", stream.read(4))[0]

            if ace_size < 8 or ace_pos + ace_size > len(sd_raw):
                print(f"[!] Skipping ACE #{ace_index}: Invalid ace_size={ace_size}")
                continue

            ace_data = stream.read(ace_size - 8)
            if ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT_ACE
                object_flags = struct.unpack("<I", ace_data[0:4])[0]
                offset = 4

                guid = None
                if object_flags & 0x1:  # ObjectType GUID
                    if len(ace_data) < offset + 16:
                        print(f"[!] Skipping ACE #{ace_index}: Truncated GUID")
                        continue
                    object_type_guid = uuid.UUID(bytes_le=ace_data[offset:offset + 16])
                    guid = str(object_type_guid)
                    offset += 16
                if object_flags & 0x2:  # InheritedObjectType GUID
                    offset += 16

                sid = format_sid(ace_data[offset:])

                if guid in REPL_GUIDS and access_mask & 0x100:
                    print(f"[!] Found potential DCSync right: {REPL_GUIDS[guid]} | SID: {sid}")
                    user_entry = resolve_sid_to_entry(sid, conn, base_dn)
                    if user_entry:
                        dump_user_info(user_entry, REPL_GUIDS[guid])
        except Exception as e:
            print(f"[!] Error parsing ACE #{ace_index}: {e}")
        finally:
            # Ensure stream moves forward safely
            stream.seek(ace_pos + ace_size if 'ace_size' in locals() else ace_pos + 8)

# --- Connect to LDAP ---
server = Server(dc_ip, get_info=ALL)
conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)

# --- Get Base DN ---
conn.search(search_base="", search_filter="(objectClass=*)", search_scope=BASE, attributes=["namingContexts"])
base_dn = conn.entries[0]["namingContexts"][0]
print(f"[+] Domain DN: {base_dn}")

# --- Get Security Descriptors from multiple objects ---
sd_control = security_descriptor_control(sdflags=0x04)
containers_to_check = [
    base_dn,
    f"CN=Users,{base_dn}",
    f"CN=AdminSDHolder,CN=System,{base_dn}"
]

for dn in containers_to_check:
    print(f"\n[*] Checking ACL on: {dn}")
    conn.search(search_base=dn, search_filter="(objectClass=*)", search_scope=BASE,
                attributes=["nTSecurityDescriptor"], controls=sd_control)
    if conn.entries:
        attr = conn.entries[0]["nTSecurityDescriptor"]
        if hasattr(attr, 'raw_values') and attr.raw_values:
            sd_bytes = attr.raw_values[0]
            print(f"[DEBUG] Raw descriptor length: {len(sd_bytes)}")
            check_acl_for_dcsync(sd_bytes, conn, base_dn)
        else:
            print("[!] No nTSecurityDescriptor found.")

    else:
        print(f"[!] Failed to retrieve ACL from: {dn}")
