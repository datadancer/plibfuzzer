#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <iostream>
#include "FuzzerDefs.h"
#include "FuzzerCorpus.h"
#include "FuzzerShare.h"
#include "FuzzerIO.h"
namespace fuzzer {

//Create a shared in-memory test case log for the calling instance identified by id;
//tc_size indicates the size of the metadata of a test case
//The log stack is : mutex sp data data data data
int CreateLog(int id) {
    key_t key = ftok(".", id);
    int shmid = shmget(key, MAX_SHM, IPC_CREAT | IPC_EXCL | 0666);
    if (shmid < 0) {
    	shmid = shmget(key, MAX_SHM, 0666);
    	if (shmid < 0) {
            perror("shmget error");
            exit(1);
	}
    }

    myshmid = shmid;
    void * smem = shmat(shmid, NULL, 0);
    //pthread_mutex_t *mutex = (pthread_mutex_t *)smem;
    pthread_mutexattr_t attr;
    struct MemHead *mh = (struct MemHead *)smem;

    if (pthread_mutexattr_init(&attr)){
        perror("pthread_mutexattr_init");
        return 0;
    }
    if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
        perror("pthread_mutexattr_setpshared");
        return 0;
    }
    if (pthread_mutex_init(&mh->mutex, &attr)){
        perror("pthread_mutex_init");
        return 0;
    }

    mh->sp = 0;
    MyLog = smem;
    Printf("Process %d: Create log %d success starting at %p, sp=%lx\n", id, shmid, smem, mh->sp);
    return 1;
}

//Attach to the test case log belonging to the fuzzer instance id
int AttachLog(int id) {
    key_t key = ftok(".", id);
    int shmid;
    for(int i=0;i<20;i++){
    shmid = shmget(key, MAX_SHM, 0666);
    	if (shmid < 0) {
    	    sleep(1);
    	    Printf("Process %d: Attach log failed %d times. Try again\n", id, i);
    	}
    }

    if (shmid < 0) {
	perror("shmget");
	exit(1);
    }

    NeighborLog = shmat(shmid, NULL, 0);
    struct MemHead *mh = (struct MemHead *)NeighborLog;
    Printf("Process %d: Attach log %d success starting at %p, sp=%lx\n", id, shmid, NeighborLog, mh->sp);
    return shmid;
}

//Push a newly generated test case tc into log
//During fuzzing, a fuzzer pushes the executed test case information to
//its test case log if the test case is interesting (push_testcase())
//at the end of each fuzzing run;

template<typename T>
void PushVector(void *spbottom, struct MemHead *mhead, Vector<T> *V){
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    T *u = (T *)sptop; T *data = V->data();
    for(int i=0; i<V->size(); i++) u[i] = data[i];

    size_t size = V->size()*sizeof(T);
    mhead->sp += size;

    sptop = static_cast<char*>(spbottom) + mhead->sp;
    *(size_t *)sptop = size;
    mhead->sp += sizeof(size_t);
}

template<typename T>
void PopVector(void *spbottom, struct MemHead *mhead, Vector<T> *V){
    mhead->sp -= sizeof(size_t);
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    size_t size = *(size_t *)sptop;

    mhead->sp -= size;
    sptop = static_cast<char*>(spbottom) + mhead->sp;
    T *u = (T *) sptop;
    for(int i=0;i<size/(sizeof(T));i++) V->push_back(u[i]);
}

template <typename T>
void PushValue(void * spbottom, struct MemHead *mhead, T value){
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    *(T *)sptop = value;
    mhead->sp += sizeof(T);
}

template <typename T>
void PopValue(void * spbottom, struct MemHead *mhead, T * value){
    mhead->sp -= sizeof(T);
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    *value = *(T *)sptop;
}

void PushSha1(void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]){
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    memcpy(sptop, Sha1, kSHA1NumBytes);
    mhead->sp += kSHA1NumBytes;
}

void PopSha1( void * spbottom, struct MemHead *mhead, uint8_t Sha1[kSHA1NumBytes]){
    mhead->sp -= kSHA1NumBytes;
    void * sptop = static_cast<char*>(spbottom) + mhead->sp;
    memcpy(Sha1, sptop, kSHA1NumBytes);
}

void PushInputInfo(InputInfo *II) {
    //Push II to MyLog
    if(MyLog == NULL) { Printf("Please CreateLog first\n"); exit(1); }
    struct MemHead *mhead = (struct MemHead *)MyLog;
    pthread_mutex_t * mutex = &mhead->mutex;

    size_t m_size = II->U.size() + II->UniqFeatureSet.size() + II->DataFlowTraceForFocusFunction.size() +
        sizeof(II->NumFeatures)*4+sizeof(II->Reduced)*3+sizeof(struct MemHead) + mhead->sp;
    if(m_size >= MAX_SHM) {
	Printf("Share space is full, skip this InputInfo.\n");
	return;
    }
    pthread_mutex_lock(mutex);

    void * spbottom = static_cast<char*>(MyLog) + sizeof(struct MemHead);

    PushVector(spbottom, mhead, &II->U);
    PushSha1(spbottom, mhead, II->Sha1);
    PushValue(spbottom, mhead, II->NumFeatures);
    PushValue(spbottom, mhead, II->Tmp);
    PushValue(spbottom, mhead, II->NumExecutedMutations);
    PushValue(spbottom, mhead, II->NumSuccessfullMutations);
    PushValue(spbottom, mhead, II->MayDeleteFile);
    PushValue(spbottom, mhead, II->Reduced);
    PushValue(spbottom, mhead, II->HasFocusFunction);
    PushValue(spbottom, mhead, II->KeyRing);
    PushVector(spbottom, mhead, &II->UniqFeatureSet);
    PushVector(spbottom, mhead, &II->DataFlowTraceForFocusFunction);

    NumberOfPushedLogs++;
    pthread_mutex_unlock(mutex);
}

//Fetch a test case from the test case log of the instance id into tc
//At the syncing phase, a fuzzer pops a test case from its neighbor 
//(pop_testcase()) to examine whether the test case is useful or not.

InputInfo *PopInputInfo() {
    //Pop II from NeighborLog
    if(NeighborLog == NULL)  return NULL; 

    struct MemHead *mhead = (struct MemHead *)NeighborLog;
    pthread_mutex_t * mutex = &mhead->mutex;

    if( mhead->sp == 0){
	return NULL;
    }

    pthread_mutex_lock(mutex);
    void * spbottom = static_cast<char*>(NeighborLog) + sizeof(struct MemHead);
    InputInfo *II = new InputInfo();

    PopVector(spbottom, mhead, &II->DataFlowTraceForFocusFunction);
    PopVector(spbottom, mhead, &II->UniqFeatureSet);
    PopValue(spbottom, mhead, &II->KeyRing);
    PopValue(spbottom, mhead, &II->HasFocusFunction);
    PopValue(spbottom, mhead, &II->Reduced);
    PopValue(spbottom, mhead, &II->MayDeleteFile);
    PopValue(spbottom, mhead, &II->NumSuccessfullMutations);
    PopValue(spbottom, mhead, &II->NumExecutedMutations);
    PopValue(spbottom, mhead, &II->Tmp);
    PopValue(spbottom, mhead, &II->NumFeatures);
    PopSha1(spbottom, mhead, II->Sha1);
    PopVector(spbottom, mhead, &II->U);

    NumberOfPopedLogs++;

    pthread_mutex_unlock(mutex);
    return II;
}

//Flush out all the stale test cases from the instance id by force
void FlushLog(int id) {

}

//Destroy the test case log owned by the instance id
//The log is eventually destroyed by the fuzzer (close_log())
//when fuzzing ends.
void CloseLog(int id) {
    shmdt(MyLog);
    shmdt(NeighborLog);
    if(shmctl(myshmid, IPC_RMID, NULL) < 0){
        perror("shmctl");
    }
}

void displayInputInfo(InputInfo *II){
    std::cout<<"U: ";
    for(const uint8_t & k : II->U) std::cout<<std::oct<<k<<" ";
    auto Sha1Str = Sha1ToString(II->Sha1);
    std::cout<<Sha1Str<<std::endl;

    std::cout<<II->NumFeatures<<" "<<II->Tmp<<" "<<II->NumExecutedMutations<<" "<<II->NumSuccessfullMutations<<" ";
    std::cout<<II->MayDeleteFile<<" "<<II->MayDeleteFile<<" "<<II->Reduced<<std::endl;
    std::cout<<"UniqFeatureSet: "; 
    for(const uint32_t & k : II->UniqFeatureSet) std::cout<<std::hex<<k<<" "; std::cout<<std::endl;
    std::cout<<"DataFlowTraceForFocusFunction: "; 
    for(const uint8_t & k : II->DataFlowTraceForFocusFunction) std::cout<<std::oct<<k<<" "; std::cout<<std::endl;
}

}
int tmain(int argc, char **argv){
    if(argc != 3) {
        printf("Usage: %s <ID> <N>\n", argv[0]);
        return -1;
    }

    int ID = atoi(argv[1]);
    int N = atoi(argv[2]);
    if (ID >= N) { std::cout<<"ERROR ID is bigger than N\n"; return 1; }
    int err;
    err = fuzzer::CreateLog(ID);
    if(!err) {
	std::cout<<"CreateLog error"<<std::endl;
	return 1;
    }

    std::cout<<"CreateLog done.\n";
    std::cin>>err;

    err = fuzzer::AttachLog((ID+1)%N);
    if(!err) {
	std::cout<<"AttachLog error"<<std::endl;
	return 1;
    }

    fuzzer::InputInfo II;
    II.U.push_back(ID + 'A');
    II.U.push_back(ID + 'E');
    II.U.push_back(ID + 'I');
    II.U.push_back(ID + 'O');
    II.U.push_back(ID + 'U');
    fuzzer::ComputeSHA1(II.U.data(), II.U.size(), II.Sha1);

    for(int i=0;i<10;i++){
        II.DataFlowTraceForFocusFunction.push_back('A' + ID + i);
    }

    for(int i=0;i<20;i++){
        II.UniqFeatureSet.push_back(((ID+1)<<4)+i);
    }

    II.HasFocusFunction = true;
    int loopcount = 0;

    while(true) {
	if(loopcount++ > 100) break;
    	fuzzer::PushInputInfo(&II);

    	printf("\nProcess %d Say: Put II\n", ID);
	displayInputInfo(&II);
    	
    	fuzzer::InputInfo *II2;

    	II2 = fuzzer::PopInputInfo();
	if (II2 == NULL) continue;

    	printf("\nProcess %d Say: Get II\n", ID);
	displayInputInfo(II2);

	delete II2;
    }

    return 0;
}

//int main(int argc, char **argv){
//    return tmain(argc, argv);
//}
