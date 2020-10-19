#pragma once

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define BIT_SET(x) 		(1ULL<<(x))
#define BIT_VAL(b,val) 	(((val) >> (b)) & 1)
#define KB(x) 			((x)<<10ULL)
#define MB(x) 			((x)<<20ULL)
#define GB(x) 			((x)<<30ULL)
#define CL_SHIFT 		6
#define CL_SIZE 		64
#define PAGE_SIZE 		4096
#define ROW_SIZE 		(8<<10)

#define ALIGN_TO(X, Y) ((X) & (~((1LL<<(Y))-1LL)))	// Mask out the lower Y bits
#define LS_BITMASK(X)  ((1LL<<(X))-1LL)	// Mask only the lower X bits

// Flags 
#define F_CLEAR 			0L
#define F_VERBOSE 			BIT_SET(0)
#define F_EXPORT 			BIT_SET(1)
#define F_CONFIG			BIT_SET(2)
#define F_NO_OVERWRITE		BIT_SET(3)
#define MEM_SHIFT			(30L)
#define MEM_MASK			0b11111ULL << MEM_SHIFT
#define F_ALLOC_HUGE 		BIT_SET(MEM_SHIFT)
#define F_ALLOC_HUGE_1G 	F_ALLOC_HUGE | BIT_SET(MEM_SHIFT+1)
#define F_ALLOC_HUGE_2M		F_ALLOC_HUGE | BIT_SET(MEM_SHIFT+2)
#define F_POPULATE			BIT_SET(MEM_SHIFT+3)

#define NOT_FOUND 	((void*) -1)
#define	NOT_OPENED  -1

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1e9 + (ts)->tv_nsec)

//----------------------------------------------------------
//                      Static functions

static inline __attribute__ ((always_inline))
void clflush(volatile void *p)
{
	asm volatile ("clflush (%0)\n"::"r" (p):"memory");
}

static inline __attribute__ ((always_inline))
void clflushopt(volatile void *p)
{
#ifdef DDR3
	asm volatile ("clflush (%0)\n"::"r" (p):"memory");
#else
	asm volatile ("clflushopt (%0)\n"::"r" (p):"memory");
#
#endif
}

static inline __attribute__ ((always_inline))
void cpuid()
{
	asm volatile ("cpuid":::"rax", "rbx", "rcx", "rdx");
}

static inline __attribute__ ((always_inline))
void mfence()
{
	asm volatile ("mfence":::"memory");
}

static inline __attribute__ ((always_inline))
void sfence()
{
	asm volatile ("sfence":::"memory");
}

static inline __attribute__ ((always_inline))
void lfence()
{
	asm volatile ("lfence":::"memory");
}

static inline __attribute__ ((always_inline))
uint64_t rdtscp(void)
{
	uint64_t lo, hi;
	asm volatile ("rdtscp\n":"=a" (lo), "=d"(hi)
		      ::"%rcx");
	return (hi << 32) | lo;
}

static inline __attribute__ ((always_inline))
uint64_t rdtsc(void)
{
	uint64_t lo, hi;
	asm volatile ("rdtsc\n":"=a" (lo), "=d"(hi)
		      ::"%rcx");
	return (hi << 32) | lo;
}

static inline __attribute__ ((always_inline))
uint64_t realtime_now()
{
	struct timespec now_ts;
	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	return TIMESPEC_NSEC(&now_ts);
}

// void set_physmap(mem_buff_t* mem);

// pte_t get_pte(char* v_addr, mem_buff_t* mem);

// addr_tuple reverse_addr_tuple(uint64_t p_addr, mem_buff_t* mem);

//----------------------------------------------------------
//                      Helpers 
int gt(const void *a, const void *b);

double mean(uint64_t * vals, size_t size);

uint64_t median(uint64_t * vals, size_t size);

char *bit_string(uint64_t val);

char *int_2_bin(uint64_t val);

char *get_rnd_addr(char *base, size_t m_size, size_t align);

int get_rnd_int(int min, int max);

