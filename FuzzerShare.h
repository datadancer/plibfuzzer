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

#define MAX_FILE_SIZE 1024*100

struct InputInfoLog {
    int filesz; //filesize no large than 10K
    uint8_t U[MAX_FILE_SIZE];//filesize no large than 10K
    uint8_t Sha1[kSHA1NumBytes];  // Checksum.
    size_t NumFeatures = 0;
    size_t Tmp = 0; // Used by ValidateFeatureSet.
    size_t NumExecutedMutations = 0;
    size_t NumSuccessfullMutations = 0;
    int KeyRing = 0;
    bool MayDeleteFile = false;
    bool Reduced = false;
    bool HasFocusFunction = false;
    int UniqFeatureSetSize = 0;
    uint8_t UniqFeatureSet[1024];//filesize no large than 10K
    int DataFlowTraceForFocusFunctionSize = 0;
    uint8_t DataFlowTraceForFocusFunction[1024];//filesize no large than 10K
};

static long * HEAD; //HEAD of current process
static int * TAIL; //TAIL of current process
static long TAILS[120] = {}; //Tails of other fuzzers
static int ID;
static int TOTAL;
static void * NeighborLog[120] = {};

static long NumberOfPopedLogs = 0;
static long NumberOfPushedLogs = 0;
static void * MyLog = NULL;
static int myshmid = 0;
static size_t MAX_SHM = 1024*1024*100;
static size_t NUM_LOGS = MAX_SHM/sizeof(InputInfoLog);

//Create a shared in-memory test case log for the calling instance identified by id;
//tc_size indicates the size of the metadata of a test case
//The log stack is : mutex sp data data data data
int CreateLog(int id, int total);

void PrintLogStats();
//Attach to the test case log belonging to the fuzzer instance id
int AttachLog(int id);
int AttachLog();

//Push a newly generated test case tc into log
//During fuzzing, a fuzzer pushes the executed test case information to
//its test case log if the test case is interesting (push_testcase())
//at the end of each fuzzing run;

//template<typename T>
//void PushVector(void *spbottom, struct MemHead *mhead, Vector<T> *V);
//
//template<typename T>
//void PopVector(void *spbottom, struct MemHead *mhead, Vector<T> *V);
//
//template <typename T>
//void PushValue(void * spbottom, struct MemHead *mhead, T value);
//
//template <typename T>
//void PopValue(void * spbottom, struct MemHead *mhead, T * value);
//
//void PushSha1(void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]);
//
//void PopSha1( void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]);

void PushInputInfo(InputInfo *II);

//Fetch a test case from the test case log of the instance id into tc
//At the syncing phase, a fuzzer pops a test case from its neighbor 
//(pop_testcase()) to examine whether the test case is useful or not.

InputInfo *PopOneInputInfo(struct InputInfoLog &log);
void PopInputInfo(Vector<InputInfo*> &IIV);

//Flush out all the stale test cases from the instance id by force
void FlushLog(int id);

//Destroy the test case log owned by the instance id
//The log is eventually destroyed by the fuzzer (close_log())
//when fuzzing ends.
void CloseLog(int id);

void displayInputInfo(InputInfo *II);

}

