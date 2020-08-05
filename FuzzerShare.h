#include<stdio.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<unistd.h>
#include<stdlib.h>
#include<pthread.h>
#include<iostream>
#include "FuzzerDefs.h"
#include "FuzzerCorpus.h"

namespace fuzzer {

struct MemHead {
    pthread_mutex_t mutex;
    size_t sp;
};
static long NumberOfPopedLogs = 0;
static long NumberOfPushedLogs = 0;
static void * MyLog = NULL;
static int myshmid = 0;
static void * NeighborLog = NULL;
static size_t MAX_SHM = 100*1024*1024;
//Create a shared in-memory test case log for the calling instance identified by id;
//tc_size indicates the size of the metadata of a test case
//The log stack is : mutex sp data data data data
int CreateLog(int id);

void PrintLogStats();
//Attach to the test case log belonging to the fuzzer instance id
int AttachLog(int id);

//Push a newly generated test case tc into log
//During fuzzing, a fuzzer pushes the executed test case information to
//its test case log if the test case is interesting (push_testcase())
//at the end of each fuzzing run;

template<typename T>
void PushVector(void *spbottom, struct MemHead *mhead, Vector<T> *V);

template<typename T>
void PopVector(void *spbottom, struct MemHead *mhead, Vector<T> *V);

template <typename T>
void PushValue(void * spbottom, struct MemHead *mhead, T value);

template <typename T>
void PopValue(void * spbottom, struct MemHead *mhead, T * value);

void PushSha1(void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]);

void PopSha1( void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]);

void PushInputInfo(InputInfo *II);

//Fetch a test case from the test case log of the instance id into tc
//At the syncing phase, a fuzzer pops a test case from its neighbor 
//(pop_testcase()) to examine whether the test case is useful or not.

InputInfo *PopInputInfo();

//Flush out all the stale test cases from the instance id by force
void FlushLog(int id);

//Destroy the test case log owned by the instance id
//The log is eventually destroyed by the fuzzer (close_log())
//when fuzzing ends.
void CloseLog(int id);

void displayInputInfo(InputInfo *II);

}

