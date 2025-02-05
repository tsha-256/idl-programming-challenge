import sys

def load_pmp_config(file_path):
    """Loads PMP configuration from the given file."""
    with open(file_path, 'r') as f:
        lines = [line.strip() for line in f.readlines()]
        pmpcfg = [int(lines[i], 16) for i in range(64)]  # First 64 lines are pmpNcfg
        pmpaddr = [int(lines[i], 16) for i in range(64, 128)]  # Last 64 lines are pmpaddrN
            
        return pmpcfg, pmpaddr

def check_pmp_access(pmpcfg, pmpaddr, addr, mode):
    """Checks whether the given address would cause an access fault."""
    addr_match = False
    for i in range(64):
        cfg = pmpcfg[i]
        addr_0 = pmpaddr[i] << 2  # Convert PMP address format
        L = (cfg >> 7) & 0b1  # Lock bit
        O = (cfg >> 5) & 0b11 # Unused bits
        A = (cfg >> 3) & 0b11 # Address-matching mode
        X = (cfg >> 2) & 0b1  # Execute permission
        W = (cfg >> 1) & 0b1  # Write permission
        R = (cfg >> 0) & 0b1  # Read permission
        
        rwx = (0, 0, 0)  # Default deny

        if A == 0b00: # Null (Disabled)
            continue
        elif A == 0b01:  # TOR
            if i == 0:
                prev_addr = 0
            else:
                prev_addr = pmpaddr[i - 1] << 2
            
            if prev_addr <= addr < addr_0:
                addr_match = True
        elif A == 0b10:  # NA4
            if addr_0 <= addr < addr_0 + 4:
                addr_match = True
        elif A == 0b11:  # NAPOT
            trail = 0
            while pmpaddr[i] & (1 << trail) != 0:
                trail += 1  
            size = 1 << (trail + 3)
            if addr_0 <= addr < addr_0 + size:
                addr_match = True

        if addr_match:
            rwx = (R, W, X)
            break

    # for ends here
    if addr_match == False: # No PMP entry matched
        if mode == 'M': # Machine mode default allow
            return (1, 1, 1)
        else: # User/Supervisor mode default deny
            return (0, 0, 0)
    if mode == 'M': # If address matched and in machine mode and lock bit is not set, allow
        if L == 0:
            return (1, 1, 1)
    return rwx # if L is set or not in machine mode, return the permissions

def main():
    if len(sys.argv) != 5:
        print("Usage: pmp_check <pmp_config_file> <physical_address> <mode> <operation>")
        sys.exit(1)
    
    fp = sys.argv[1]
    addr = int(sys.argv[2], 16)
    mode = sys.argv[3]
    op = sys.argv[4]
    
    if mode not in {'M', 'S', 'U'}:
        print("Invalid mode. Mode must be M/S/U.")
        sys.exit(1)    
    if op not in {'R', 'W', 'X'}:
        print("Invalid operation. Operation must be R/W/X.")
        sys.exit(1)
    
    pmpcfg, pmpaddr = load_pmp_config(fp)
    R, W, X = check_pmp_access(pmpcfg, pmpaddr, addr, mode)
    
    if (op == 'R' and R) or (op == 'W' and W) or (op == 'X' and X):
        print("Access allowed.")
    else:
        print("Access fault.")

if __name__ == "__main__":
    main()
