#define DMALLOC_DISABLE 1
#include "dmalloc.hh"
#include <cassert>
#include <cstring>
#include <climits>
#include <unordered_map>

dmalloc_stats global_stats;
static std::unordered_map<uintptr_t,dmalloc_leak_value> leakMap;
/**
 * dmalloc(sz,file,line)
 *      malloc() wrapper. Dynamically allocate the requested amount `sz` of memory and 
 *      return a pointer to it 
 * 
 * @arg size_t sz : the amount of memory requested 
 * @arg const char *file : a string containing the filename from which dmalloc was called 
 * @arg long line : the line number from which dmalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dmalloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    size_t nsz = sz + 1 + 2 * sizeof(size_t);
    if (nsz<sz){
        global_stats.nfail += 1;
        global_stats.fail_size += sz;
        return nullptr;
    }
    size_t* malloc_ptr = (size_t*)base_malloc(nsz);

    if (malloc_ptr != nullptr){
        global_stats.ntotal += 1;
        global_stats.total_size += sz;
        global_stats.nactive += 1;
        global_stats.active_size += sz;
        *malloc_ptr = (uintptr_t)malloc_ptr;
        *(malloc_ptr + 1) = sz;
        char * ptr = (char*)(malloc_ptr + 2);
        if (global_stats.heap_max == 0 || (uintptr_t)ptr + sz >= global_stats.heap_max){
            global_stats.heap_max = (uintptr_t)ptr + sz ;
        }
        if (global_stats.heap_min == 0 || (uintptr_t)ptr <= global_stats.heap_min){
            global_stats.heap_min = (uintptr_t)ptr;
        }
        dmalloc_leak_value value;
        value.active = true;
        value.line = line;
        value.ptr = (uintptr_t)ptr;
        value.size = sz;
        value.file = (char*)malloc(strlen(file)*sizeof(char));
        memcpy(value.file,file, strlen(file)+1);
        leakMap.insert(std::make_pair<uintptr_t,dmalloc_leak_value>((uintptr_t)ptr,std::move(value)));
        *(ptr+sz) = '*';
        return (void*)ptr;
    }else{
        global_stats.nfail += 1;
        global_stats.fail_size += sz;
        return nullptr;
    }
}

/**
 * dfree(ptr, file, line)
 *      free() wrapper. Release the block of heap memory pointed to by `ptr`. This should 
 *      be a pointer that was previously allocated on the heap. If `ptr` is a nullptr do nothing. 
 * 
 * @arg void *ptr : a pointer to the heap 
 * @arg const char *file : a string containing the filename from which dfree was called 
 * @arg long line : the line number from which dfree was called 
 */
void dfree(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    if (ptr!=nullptr){
        if ((uintptr_t)ptr > global_stats.heap_max || (uintptr_t)ptr < global_stats.heap_min){
            fprintf(stderr,"MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",file,line,ptr);
            return;
        }
        void* mptr = (void*)(((uintptr_t)ptr/sizeof(size_t))*(sizeof(size_t)));
        size_t* malloc_ptr = (size_t*)mptr - 2;
        if ((uintptr_t)malloc_ptr != *malloc_ptr){
            fprintf(stderr,"MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",file,line,ptr);
            return;
        }
        size_t sz = *(malloc_ptr + 1);
        if (sz == 0){
            fprintf(stderr,"MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n",file,line,ptr);
            return;
        }
        char* checkBounder = (char*)ptr+sz;
        if (*checkBounder!='*'){
            fprintf(stderr,"MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",file,line,ptr);
            abort();
        }
        global_stats.nactive -= 1;
        global_stats.active_size -= sz;
        std::unordered_map<uintptr_t,dmalloc_leak_value>::const_iterator got = leakMap.find ((uintptr_t)ptr);
        if (got != leakMap.end()){
            leakMap.erase(got);
        }
        *(malloc_ptr + 1) = 0;
        base_free(malloc_ptr);
    }
}

/**
 * dcalloc(nmemb, sz, file, line)
 *      calloc() wrapper. Dynamically allocate enough memory to store an array of `nmemb` 
 *      number of elements with wach element being `sz` bytes. The memory should be initialized 
 *      to zero  
 * 
 * @arg size_t nmemb : the number of items that space is requested for
 * @arg size_t sz : the size in bytes of the items that space is requested for
 * @arg const char *file : a string containing the filename from which dcalloc was called 
 * @arg long line : the line number from which dcalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dcalloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test014).
    if (nmemb >= UINT_MAX/sz){
        global_stats.nfail += 1;
        return nullptr;
    }
    void* ptr = dmalloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}

/**
 * get_statistics(stats)
 *      fill a dmalloc_stats pointer with the current memory statistics  
 * 
 * @arg dmalloc_stats *stats : a pointer to the the dmalloc_stats struct we want to fill
 */
void get_statistics(dmalloc_stats* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_stats));
    // Your code here.
    memcpy(stats, &global_stats, sizeof(dmalloc_stats));
}

/**
 * print_statistics()
 *      print the current memory statistics to stdout       
 */
void print_statistics() {
    dmalloc_stats stats;
    get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

/**  
 * print_leak_report()
 *      Print a report of all currently-active allocated blocks of dynamic
 *      memory.
 */
void print_leak_report() {
    // Your code here.
    for ( const auto& [key, value] : leakMap){
        if (value.active){
            fprintf(stdout,"LEAK CHECK: %s:%ld: allocated object %#lx with size %ld\n",value.file,value.line,value.ptr,value.size);
        }
    }
}
