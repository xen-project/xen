mem_caching_attr = {
    'UC' : 0,
    'WC' : 1,
    'WT' : 4,
    'WP' : 5,
    'WB' : 6,
    };

e820_mem_type = {
    'AddressRangeMemory'    : 1,
    'AddressRangeReserved'  : 2,
    'AddressRangeACPI'      : 3,
    'AddressRangeNVS'       : 4,
    'AddressRangeIO'        : 16,
    'AddressRangeShared'    : 17,
};

MT_COL = 2
MA_COL = 3

def strmap(row):
   if (type(row) != type([])):
       return row
   row[MT_COL] = e820_mem_type[row[MT_COL]]
   row[MA_COL] = mem_caching_attr[row[MA_COL]]
   return row

def memmap_parse(memmap):
    return map(strmap, memmap)

if __name__ == '__main__':
   memmap = [ 'memmap',
              [ '1', '2', 'AddressRangeMemory', 'UC'],
              [ '1', '2', 'AddressRangeReserved', 'UC'],
              [ '1', '2', 'AddressRangeACPI', 'WB'],
              [ '1', '2', 'AddressRangeNVS', 'WB'],
              [ '1', '2', 'AddressRangeIO', 'WB'],
              [ '1', '2', 'AddressRangeShared', 'WB']]
   print memmap_parse(memmap);


