import os
import time
import zipfile

# Colour styling in terminal
RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RESET = '\033[0m' 

# Precise magic number definitions with offsets
magic_numbers = {
    # --- Images ---
    "png":     (0, bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])),
    "jpg":     (0, bytes([0xFF, 0xD8, 0xFF, 0xE0])),  # JFIF
    "jpeg":    (0, bytes([0xFF, 0xD8, 0xFF, 0xE1])),  # EXIF
    "gif":     (0, bytes([0x47, 0x49, 0x46, 0x38])),
    "bmp":     (0, bytes([0x42, 0x4D])),
    "tif":     (0, bytes([0x49, 0x49, 0x2A, 0x00])),
    "tiff":    (0, bytes([0x4D, 0x4D, 0x00, 0x2A])),  # Big-endian TIFF
    "webp":    (0, bytes([0x52, 0x49, 0x46, 0x46])),
    "ico":     (0, bytes([0x00, 0x00, 0x01, 0x00])),

    # --- Archives / Compression ---
    "zip":     (0, bytes([0x50, 0x4B, 0x03, 0x04])),
    "gz":      (0, bytes([0x1F, 0x8B])),
    "tar":     (257, bytes([0x75, 0x73, 0x74, 0x61, 0x72])),  # offset 257
    "7z":      (0, bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])),
    "rar":     (0, bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])),
    
    # --- Documents ---
    "pdf":     (0, bytes([0x25, 0x50, 0x44, 0x46])),
    "ps":      (0, bytes([0x25, 0x21, 0x50, 0x53])),
    "ole2":    (0, bytes([0xD0, 0xCF, 0x11, 0xE0])),  # Generic OLE2 (doc/xls/ppt)

    # --- Audio ---
    "mp3":     (0, bytes([0xFF, 0xFB])),
    "mp3_v1":  (0, bytes([0xFF, 0xFA])),  # MP3 variant
    "wav":     (0, bytes([0x52, 0x49, 0x46, 0x46])),
    "flac":    (0, bytes([0x66, 0x4C, 0x61, 0x43])),
    "ogg":     (0, bytes([0x4F, 0x67, 0x67, 0x53])),
    "midi":    (0, bytes([0x4D, 0x54, 0x68, 0x64])),

    # --- Video ---
    "mp4":     (4, bytes([0x66, 0x74, 0x79, 0x70])),  # offset 4
    "avi":     (0, bytes([0x52, 0x49, 0x46, 0x46])),
    "mov":     (4, bytes([0x66, 0x74, 0x79, 0x70, 0x71, 0x74])),  # QuickTime

    # --- Executables / System ---
    "exe":     (0, bytes([0x4D, 0x5A])),
    "dll":     (0, bytes([0x4D, 0x5A])),
    "elf":     (0, bytes([0x7F, 0x45, 0x4C, 0x46])),
    "class":   (0, bytes([0xCA, 0xFE, 0xBA, 0xBE])),
    "sh":      (0, bytes([0x23, 0x21])),  # shebang

    # --- Font Files ---
    "ttf":     (0, bytes([0x00, 0x01, 0x00, 0x00, 0x00])),
    "otf":     (0, bytes([0x4F, 0x54, 0x54, 0x4F])),

    # --- Disk Images ---
    "iso":     (0x8001, bytes([0x43, 0x44, 0x30, 0x30, 0x31])),

    # --- Other ---
    "xml":     (0, bytes([0x3C, 0x3F, 0x78, 0x6D, 0x6C])),
    "rtf":     (0, bytes([0x7B, 0x5C, 0x72, 0x74, 0x66])),
    "swf":     (0, bytes([0x43, 0x57, 0x53])),
    "wasm":    (0, bytes([0x00, 0x61, 0x73, 0x6D])),
}

'''
Turns out, modern office files such as .docx, .pptx, and .xlsx are actually ZIP files in disguise
that uses the same magic number ( 50 4B 03 04 ) in hexadecimal
'''
def detect_office_format(file_path):
    """Detect MS Office format by checking internal structure"""
    # Exception handling
    try:
        # Check if it's a ZIP-based Office file
        '''
        When you check a ZIP-based office file, it's going to contain multiple files
        We can check what the file is by checking what it starts with:
            word/ -> Word Document
            xl/ -> Excel document
            ppt/ -> Powerpoint document
        '''
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()
                if 'word/' in str(names):
                    return 'docx'
                elif 'xl/' in str(names):
                    return 'xlsx'
                elif 'ppt/' in str(names):
                    return 'pptx'
                else:
                    return 'zip'
        return None
    except:
        return None


def identify_file_type(file_path):
    """Identify file type by magic number with offset support"""
    # Read enough bytes to check all signatures. 0x8010 is enough for ISO signatures
    # Some files hide their magic numbers far into the file such as an ISO file
    max_read = 0x8010
    
    try:
        with open(file_path, 'rb') as fd:
            file_data = fd.read(max_read)
    except:
        return None
    
    # Check for Office formats first (they use common signatures)
    office_type = detect_office_format(file_path)
    if office_type and office_type != 'zip':
        return office_type
    
    # Check magic numbers with offset support
    # Sometimes multiple types might match initially
    matches = []
    for ext, (offset, magic) in magic_numbers.items():
        # Check if we have enough data to read from
        if len(file_data) > offset + len(magic):
            # Read from a specific section (i.e starting position of magic number to the end of the magic number)
            if file_data[offset:offset + len(magic)] == magic:
                matches.append(ext)
    
    # Prioritize specific matches over generic ones
    if matches:
        # Remove generic types if more specific ones exist. ole2 is the generic file type of old office files
        if 'ole2' in matches and len(matches) > 1:
            matches.remove('ole2')
        if 'zip' in matches and office_type:
            return office_type
        
        # For AVI/WAV ambiguity, check further. They both start off with 'RIFF'
        if 'avi' in matches and 'wav' in matches:
            if len(file_data) > 8 and file_data[8:12] == b'WAVE':
                return 'wav'
            elif len(file_data) > 8 and file_data[8:12] == b'AVI ':
                return 'avi'
        
        return matches[0]
    
    return None


print("""
██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗     ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝    ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗    ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝""")

while True:
    print("")
    print(f"Enter the file path you want to analyse (Type {GREEN}'exit'{RESET} to leave): ", end="")
    file_path = input().strip().strip('"').strip("'")

    if file_path.lower() == 'exit':
        break

    if not os.path.exists(file_path):
        print(f"{RED}File does not exist{RESET}")
        continue
    
    if not os.path.isfile(file_path):
        print(f"{RED}Path is not a file{RESET}")
        continue

    # Read file header for display
    with open(file_path, 'rb') as fd:
        file_head = fd.read(32)  # Show first 32 bytes

    file_name, os_ext = os.path.splitext(file_path)
    print("")
    print("===========================================")
    print("")
    print(f"{BLUE}[File Name]:{RESET}             ", os.path.basename(file_name))
    print(f"{BLUE}[Magic Number (hex)]:{RESET}    ", file_head.hex()[:16])

    # Identify the real file type
    real_file_extension = identify_file_type(file_path)
    
    if real_file_extension:
        print(f"{BLUE}[Real File Extension]:{RESET}   ", real_file_extension)
    else:
        print(f"{BLUE}[Real File Extension]:{RESET}   ", f"{YELLOW}Unknown{RESET}")

    # Do the file extension extraction if it contains '.'
    if '.' in file_path:
        apparent_file_extension = file_path.rsplit('.', 1)[-1].lower()
    else:
        apparent_file_extension = "none"
    print(f"{BLUE}[File Extension Header]:{RESET} ", apparent_file_extension)

    # Compare extensions
    if real_file_extension and real_file_extension != apparent_file_extension:
        # Special case: jpeg vs jpg and tif vs tiff. Both jpeg and jpg mean the same thing and likewise with tif and tiff
        if not ((real_file_extension in ['jpg', 'jpeg'] and apparent_file_extension in ['jpg', 'jpeg']) or
                (real_file_extension in ['tif', 'tiff'] and apparent_file_extension in ['tif', 'tiff'])):
            print("")
            print(f"{RED}[WARNING]{RESET} This file's header does not align with its actual format. Do not open this file.")
            print("")
        else:
            print("")
            print(f"{GREEN}Correct file type. You're safe to use this file{RESET}")
            print("")
    elif real_file_extension == apparent_file_extension:
        print("")
        print(f"{GREEN}Correct file type. You're safe to use this file{RESET}")
        print("")
    else:
        print("")
        print(f"{YELLOW}Unable to determine if file is safe{RESET}")
        print("")

    # File stats
    stats = os.stat(file_path)
    print(f"{BLUE}[Additional Stats]:{RESET}")
    print(f"    {BLUE}[Size]:{RESET}         ", stats.st_size, "bytes")
    print(f"    {BLUE}[Last modified]:{RESET}", time.ctime(stats.st_mtime))
    print(f"    {BLUE}[Last Accessed]:{RESET}", time.ctime(stats.st_atime))
    print(f"    {BLUE}[Created]:{RESET}      ", time.ctime(stats.st_ctime))
    print("")
    print("===========================================")