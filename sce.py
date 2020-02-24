# Shellcode extractor by Massimiliano Tomassoli (2015)

import sys
import os
import datetime
import pefile

author = 'Massimiliano Tomassoli'
year = datetime.date.today().year

def dword_to_bytes(value):
    return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff]

def bytes_to_dword(bytes):
    return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) | \
    ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24)
    
def get_cstring(data, offset):
    '''
    Extracts a C string (i.e. null-terminated string) from data starting from offset.
    '''
    pos = data.find('\0', offset)
    if pos == -1:
        return None
    return data[offset:pos+1]
    
def get_shellcode_len(map_file):
    '''
    Gets the length of the shellcode by analyzing map_file (map produced by VS 2013)
    '''
    try:
        with open(map_file, 'r') as f:
            lib_object = None
            shellcode_len = None
            for line in f:
                parts = line.split()
                if lib_object is not None:
                    if parts[-1] == lib_object:
                        raise Exception('_main is not the last function of %s' % lib_object)
                    else:
                        break
                elif (len(parts) > 2 and parts[1] == '_main'):
                    # Format:
                    # 0001:00000274 _main 00401274 f shellcode.obj
                    shellcode_len = int(parts[0].split(':')[1], 16)
                    lib_object = parts[-1]
                    if shellcode_len is None:
                        raise Exception('Cannot determine shellcode length')
    except IOError:
        print('[!] get_shellcode_len: Cannot open "%s"' % map_file)
        return None
    except Exception as e:
        print('[!] get_shellcode_len: %s' % e.message)
        return None
        
    return shellcode_len

def get_shellcode_and_relocs(exe_file, shellcode_len):
    '''
    Extracts the shellcode from the .text section of the file exe_file and the string
    relocations.
    Returns the triple (shellcode, relocs, addr_to_strings).
    '''
    try:
        # Extracts the shellcode.
        pe = pefile.PE(exe_file)
        shellcode = None
        rdata = None
        for s in pe.sections:
            if s.Name == '.text\0\0\0':
                if s.SizeOfRawData < shellcode_len:
                    raise Exception('.text section too small')
                shellcode_start = s.VirtualAddress
                shellcode_end = shellcode_start + shellcode_len
                shellcode = pe.get_data(s.VirtualAddress, shellcode_len)
            elif s.Name == '.rdata\0\0':
                rdata_start = s.VirtualAddress
                rdata_end = rdata_start + s.Misc_VirtualSize
                rdata = pe.get_data(rdata_start, s.Misc_VirtualSize)
                
        if shellcode is None:
            raise Exception('.text section not found')
        if rdata is None:
            raise Exception('.rdata section not found')
        
        # Extracts the relocations for the shellcode and the referenced strings in .rdata.
        relocs = []
        addr_to_strings = {}
        for rel_data in pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in rel_data.entries[:-1]: # the last element's rvs is the base_rva (why?)
                if shellcode_start <= entry.rva < shellcode_end:
                    # The relocation location is inside the shellcode.
                    relocs.append(entry.rva - shellcode_start) # offset relative to the start of shellcode
                    string_va = pe.get_dword_at_rva(entry.rva)
                    string_rva = string_va - pe.OPTIONAL_HEADER.ImageBase
                    if string_rva < rdata_start or string_rva >= rdata_end:
                        raise Exception('shellcode references a section other than .rdata: {:#x}'.format(entry.rva))
                    str = get_cstring(rdata, string_rva - rdata_start)
                    if str is None:
                        raise Exception('Cannot extract string from .rdata')
                    addr_to_strings[string_va] = str
                    
        return (shellcode, relocs, addr_to_strings)
        
    except WindowsError:
        print('[!] get_shellcode: Cannot open "%s"' % exe_file)
        return None
    except Exception as e:
        print('[!] get_shellcode: %s' % e.message)
        return None

def dword_to_string(dword):
    return ''.join([chr(x) for x in dword_to_bytes(dword)])

def add_loader_to_shellcode(shellcode, relocs, addr_to_strings):
    if len(relocs) == 0:
        return shellcode # there are no relocations
    
    # The format of the new shellcode is:
    # call here
    # here:
    # ...
    # shellcode_start:
    # <shellcode> (contains offsets to strX (offset are from "here" label))
    # relocs:
    # off1|off2|... (offsets to relocations (offset are from "here" label))
    # str1|str2|...

    delta = 21 # shellcode_start - here
    
    # Builds the first part (up to and not including the shellcode).
    x = dword_to_bytes(delta + len(shellcode))
    y = dword_to_bytes(len(relocs))
    code = [
        0xE8, 0x00, 0x00, 0x00, 0x00,       # CALL here
                                            # here:
        0x5E,                               # POP ESI
        0x8B, 0xFE,                         # MOV EDI, ESI
        0x81, 0xC6, x[0], x[1], x[2], x[3], # ADD ESI, shellcode_start + len(shellcode) - here
        0xB9, y[0], y[1], y[2], y[3],       # MOV ECX, len(relocs)
        0xFC,                               # CLD
                                            # again:
        0xAD,                               # LODSD
        0x01, 0x3C, 0x07,                   # ADD [EDI+EAX], EDI
        0xE2, 0xFA                          # LOOP again
                                            # shellcode_start:
    ]
    
    # Builds the final part (offX and strX).
    offset = delta + len(shellcode) + len(relocs) * 4 # offset from "here" label
    final_part = [dword_to_string(r + delta) for r in relocs]
    addr_to_offset = {}
    for addr in addr_to_strings.keys():
        str = addr_to_strings[addr]
        final_part.append(str)
        addr_to_offset[addr] = offset
        offset += len(str)
        
    # Fixes the shellcode so that the pointers referenced by relocs point to the
    # string in the final part.
    byte_shellcode = [ord(c) for c in shellcode]
    for off in relocs:
        addr = bytes_to_dword(byte_shellcode[off:off+4])
        byte_shellcode[off:off+4] = dword_to_bytes(addr_to_offset[addr])
    
    return ''.join([chr(b) for b in (code + byte_shellcode)]) + ''.join(final_part)
    
def dump_shellcode(shellcode):
    '''
    Prints shellcode in C format ('\x12\x23...')
    '''
    shellcode_len = len(shellcode)
    sc_array = []
    bytes_per_row = 16
    for i in range(shellcode_len):
        pos = i % bytes_per_row
        str = ''
        if pos == 0:
            str += '"'
        str += '\\x%02x' % ord(shellcode[i])
        if i == shellcode_len - 1:
            str += '";\n'
        elif pos == bytes_per_row - 1:
            str += '"\n'
        sc_array.append(str)
    shellcode_str = ''.join(sc_array)
    print(shellcode_str)

def get_xor_values(value):
    '''
    Finds x and y such that:
    1) x xor y == value
    2) x and y doesn't contain null bytes
    Returns x and y as arrays of bytes starting from the lowest significant byte.
    '''
    # Finds a non-null missing bytes.
    bytes = dword_to_bytes(value)
    missing_byte = [b for b in range(1, 256) if b not in bytes][0]
    
    xor1 = [b ^ missing_byte for b in bytes]
    xor2 = [missing_byte] * 4
    return (xor1, xor2)

def get_fixed_shellcode_single_block(shellcode):
    '''
    Returns a version of shellcode without null bytes or None if the
    shellcode can't be fixed.
    If this function fails, use get_fixed_shellcode().
    '''
    # Finds one non-null byte not present, if any.
    bytes = set([ord(c) for c in shellcode])
    missing_bytes = [b for b in range(1, 256) if b not in bytes]
    if len(missing_bytes) == 0:
        return None # shellcode can't be fixed
    missing_byte = missing_bytes[0]
    
    (xor1, xor2) = get_xor_values(len(shellcode))
    
    code = [
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,                   # CALL $ + 4
                                                        # here:
        0xC0,                                           # (FF)C0 = INC EAX
        0x5F,                                           # POP EDI
        0xB9, xor1[0], xor1[1], xor1[2], xor1[3],       # MOV ECX, <xor value 1 for shellcode len>
        0x81, 0xF1, xor2[0], xor2[1], xor2[2], xor2[3], # XOR ECX, <xor value 2 for shellcode len>
        0x83, 0xC7, 29,                                 # ADD EDI, shellcode_begin - here
        0x33, 0xF6,                                     # XOR ESI, ESI
        0xFC,                                           # CLD
                                                        # loop1:
        0x8A, 0x07,                                     # MOV AL, BYTE PTR [EDI]
        0x3C, missing_byte,                             # CMP AL, <missing byte>
        0x0F, 0x44, 0xC6,                               # CMOVE EAX, ESI
        0xAA,                                           # STOSB
        0xE2, 0xF6                                      # LOOP loop1
                                                        # shellcode_begin:
    ]
    return ''.join([chr(x) for x in code]) + shellcode.replace('\0', chr(missing_byte))

def get_fixed_shellcode(shellcode):
    '''
    Returns a version of shellcode without null bytes. This version divides
    the shellcode into multiple blocks and should be used only if
    get_fixed_shellcode_single_block() doesn't work with this shellcode.
    '''
    # The format of bytes_blocks is
    # [missing_byte1, number_of_blocks1,
    # missing_byte2, number_of_blocks2, ...]
    # where missing_byteX is the value used to overwrite the null bytes in the
    # shellcode, while number_of_blocksX is the number of 254-byte blocks where
    # to use the corresponding missing_byteX.
    bytes_blocks = []
    shellcode_len = len(shellcode)
    i = 0
    while i < shellcode_len:
        num_blocks = 0
        missing_bytes = list(range(1, 256))
        # Tries to find as many 254-byte contiguous blocks as possible which misses at
        # least one non-null value. Note that a single 254-byte block always misses at
        # least one non-null value.
        while True:
            if i >= shellcode_len or num_blocks == 255:
                bytes_blocks += [missing_bytes[0], num_blocks]
                break
            bytes = set([ord(c) for c in shellcode[i:i+254]])
            new_missing_bytes = [b for b in missing_bytes if b not in bytes]
            if len(new_missing_bytes) != 0: # new block added
                missing_bytes = new_missing_bytes
                num_blocks += 1
                i += 254
            else:
                bytes += [missing_bytes[0], num_blocks]
                break
                
    if len(bytes_blocks) > 0x7f - 5:
        # Can't assemble "LEA EBX, [EDI + (bytes-here)]" or "JMP skip_bytes".
        return None
        
    (xor1, xor2) = get_xor_values(len(shellcode))
    
    code = ([
        0xEB, len(bytes_blocks)] +                      # JMP SHORT skip_bytes
                                                        # bytes:
        bytes_blocks + [                                # ...
                                                        # skip_bytes:
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,                   # CALL $ + 4
                                                        # here:
        0xC0,                                           # (FF)C0 = INC EAX
        0x5F,                                           # POP EDI
        0xB9, xor1[0], xor1[1], xor1[2], xor1[3],       # MOV ECX, <xor value 1 for shellcode len>
        0x81, 0xF1, xor2[0], xor2[1], xor2[2], xor2[3], # XOR ECX, <xor value 2 for shellcode len>
        0x8D, 0x5F, -(len(bytes_blocks) + 5) & 0xFF,    # LEA EBX, [EDI + (bytes - here)]
        0x83, 0xC7, 0x30,                               # ADD EDI, shellcode_begin - here
                                                        # loop1:
        0xB0, 0xFE,                                     # MOV AL, 0FEh
        0xF6, 0x63, 0x01,                               # MUL AL, BYTE PTR [EBX+1]
        0x0F, 0xB7, 0xD0,                               # MOVZX EDX, AX
        0x33, 0xF6,                                     # XOR ESI, ESI
        0xFC,                                           # CLD
                                                        # loop2:
        0x8A, 0x07,                                     # MOV AL, BYTE PTR [EDI]
        0x3A, 0x03,                                     # CMP AL, BYTE PTR [EBX]
        0x0F, 0x44, 0xC6,                               # CMOVE EAX, ESI
        0xAA,                                           # STOSB
        0x49,                                           # DEC ECX
        0x74, 0x07,                                     # JE shellcode_begin
        0x4A,                                           # DEC EDX
        0x75, 0xF2,                                     # JNE loop2
        0x43,                                           # INC EBX
        0x43,                                           # INC EBX
        0xEB, 0xE3                                      # JMP loop1
                                                        # shellcode_begin:
    ])
    
    new_shellcode_pieces = []
    pos = 0
    for i in range(len(bytes_blocks) / 2):
        missing_char = chr(bytes_blocks[i*2])
        num_bytes = 254 * bytes_blocks[i*2 + 1]
        new_shellcode_pieces.append(shellcode[pos:pos+num_bytes].replace('\0', missing_char))
        pos += num_bytes
    
    return ''.join([chr(x) for x in code]) + ''.join(new_shellcode_pieces)
    
def main():
    print("Shellcode Extractor by %s (%d)\n" % (author, year))
    
    if len(sys.argv) != 3:
        print('Usage:\n' +
        ' %s <exe file> <map file>\n' % os.path.basename(sys.argv[0]))
        return
        
    exe_file = sys.argv[1]
    map_file = sys.argv[2]
    
    print('Extracting shellcode length from "%s"...' % os.path.basename(map_file))
    shellcode_len = get_shellcode_len(map_file)
    if shellcode_len is None:
        return
    print('shellcode length: %d' % shellcode_len)
    
    print('Extracting shellcode from "%s" and analyzing relocations...' % os.path.basename(exe_file))
    result = get_shellcode_and_relocs(exe_file, shellcode_len)
    if result is None:
        return
    (shellcode, relocs, addr_to_strings) = result
    if len(relocs) != 0:
        print('Found %d reference(s) to %d string(s) in .rdata' % (len(relocs), len(addr_to_strings)))
        print('Strings:')
        for s in addr_to_strings.values():
            print(' ' + s[:-1])
        print('')
        shellcode = add_loader_to_shellcode(shellcode, relocs, addr_to_strings)
    else:
        print('No relocations found')
        
    if shellcode.find('\0') == -1:
        print('Unbelievable: the shellcode does not need to be fixed!')
        fixed_shellcode = shellcode
    else:
        # shellcode contains null bytes and needs to be fixed.
        print('Fixing the shellcode...')
        fixed_shellcode = get_fixed_shellcode_single_block(shellcode)
        if fixed_shellcode is None: # if shellcode wasn't fixed...
            fixed_shellcode = get_fixed_shellcode(shellcode)
            if fixed_shellcode is None:
                print('[!] Cannot fix the shellcode')
    
    print('final shellcode length: %d\n' % len(fixed_shellcode))
    print('char shellcode[] = ')
    dump_shellcode(fixed_shellcode)

main()