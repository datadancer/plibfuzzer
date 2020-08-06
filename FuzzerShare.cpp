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

int CreateLog(int id, int total) {
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
    HEAD = (long *)smem;
    ID = id;
    TOTAL = total;
    if(TOTAL>120) {
	    Printf("Process id is to big, no large than 120 \n");
	    return -1;
    }
    *HEAD = 0;

    MyLog = smem;
    Printf("Log size is %d. Share memory could hold %d logs\n", sizeof(struct InputInfoLog), NUM_LOGS);
    Printf("Process %d: Create log %d success starting at %p\n", id, shmid, smem);
    return 1;
}

//Attach to the test case log belonging to the fuzzer instance id
int AttachLog(int id) {
    if (id>120) {
	    Printf("Process id is to big, no large than 120 \n");
            exit(1);
    }
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

    NeighborLog[id] = shmat(shmid, NULL, 0);
    Printf("Process %d: Attach log %d success starting at %p\n", id, shmid, NeighborLog[id]);
    return shmid;
}

int AttachLog(){
	for(int i=0;i<TOTAL;i++){
		if (i==ID) continue;
		AttachLog(i);
	}
	return 0;
}

//Push a newly generated test case tc into log
//During fuzzing, a fuzzer pushes the executed test case information to
//its test case log if the test case is interesting (push_testcase())
//at the end of each fuzzing run;


void PushInputInfo(InputInfo *II) {
    if(MyLog == NULL) { Printf("Please CreateLog first\n"); exit(1); }
    void * MyLogStart = (char *)MyLog + sizeof(HEAD); //Head of MyLog is used for HEAD;
    struct InputInfoLog * logs = (struct InputInfoLog *)MyLogStart;
    struct InputInfoLog  iil = logs[(*HEAD) % NUM_LOGS];

    if (Hash(II->U).compare(Sha1ToString(II->Sha1)) != 0) {
	Printf("PUSH ERROR: Hash check failed");
    }

    iil.filesz = II->U.size();
    if(iil.filesz > MAX_FILE_SIZE) {
	    Printf("WARNING: Filesize is %zd\n", iil.UniqFeatureSetSize);
	    iil.filesz = MAX_FILE_SIZE;
    }
    memcpy(iil.U, II->U.data(), iil.filesz);
    memcpy(iil.Sha1, II->Sha1, kSHA1NumBytes);
    iil.NumFeatures = II->NumFeatures;
    iil.Tmp = II->Tmp;
    iil.NumExecutedMutations = 0;
    iil.NumSuccessfullMutations = 0;
    iil.MayDeleteFile = II->MayDeleteFile;
    iil.HasFocusFunction = II->HasFocusFunction;
    iil.KeyRing = II->KeyRing;
    iil.UniqFeatureSetSize = II->UniqFeatureSet.size();
    if (iil.UniqFeatureSetSize > 1024) {
	    Printf("WARNING: UniqFeatureSetSize is %zd\n", iil.UniqFeatureSetSize);
	    iil.UniqFeatureSetSize = 1024;//No large than 1024
    }
    memcpy(iil.UniqFeatureSet, II->UniqFeatureSet.data(), iil.UniqFeatureSetSize);

    iil.DataFlowTraceForFocusFunctionSize = II->DataFlowTraceForFocusFunction.size();
    if (iil.DataFlowTraceForFocusFunctionSize > 1024) {
	    Printf("WARNING: DataFlowTraceForFocusFunctionSize is %zd\n", iil.DataFlowTraceForFocusFunctionSize);
	    iil.DataFlowTraceForFocusFunctionSize = 1024;//No large than 1024
    }
    memcpy(iil.DataFlowTraceForFocusFunction, II->DataFlowTraceForFocusFunction.data(), iil.DataFlowTraceForFocusFunctionSize);

    NumberOfPushedLogs++;
    
    *HEAD += 1;
}

//Fetch a test case from the test case log of the instance id into tc
//At the syncing phase, a fuzzer pops a test case from its neighbor 
//(pop_testcase()) to examine whether the test case is useful or not.

InputInfo *PopOneInputInfo(struct InputInfoLog * log){
    InputInfo *II = new InputInfo();
    for(int i=0; i<log->filesz; i++){
	II->U.push_back(log->U[i]);
    }

    memcpy(II->Sha1, log->Sha1, kSHA1NumBytes);
    II->NumFeatures = log->NumFeatures;
    II->Tmp = log->Tmp;
    II->NumExecutedMutations = 0;
    II->NumSuccessfullMutations = 0;
    II->MayDeleteFile = log->MayDeleteFile;
    II->HasFocusFunction = log->HasFocusFunction;
    II->KeyRing = log->KeyRing;

    for(int i=0;i<log->DataFlowTraceForFocusFunctionSize;i++){
	II->DataFlowTraceForFocusFunction.push_back(log->DataFlowTraceForFocusFunction[i]);
    }

    for(int i=0;i<log->UniqFeatureSetSize;i++){
	II->UniqFeatureSet.push_back(log->UniqFeatureSet[i]);
    }

    if (Hash(II->U).compare(Sha1ToString(II->Sha1)) != 0) {
	Printf("POP ERROR: Hash check failed");
    }
    return II;
}

void PopInputInfo(Vector<InputInfo*> &IIV) {
    long * head;
    void * LogStart;
    struct InputInfoLog * logs; 

    for(int i=0; i<TOTAL; i++){
	if (i == ID) continue;
	void * CurrentNeighborLog = NeighborLog[i];
    	if(CurrentNeighborLog == NULL)  {
    	    //Printf("Error: Neighbor Log is null, skip popping.\n");
    	    continue;
    	}
    	head = (long *)CurrentNeighborLog;
    	LogStart = (char *)CurrentNeighborLog + sizeof(HEAD);
    	logs = (struct InputInfoLog *)LogStart;
    	for(long j=TAILS[i]; j < *head; j++){
		IIV.push_back(PopOneInputInfo(logs + (j % NUM_LOGS)));
    		NumberOfPopedLogs++;
    	}
	TAILS[i] = * head; //Update current tail
    }
}

void IncreaseNumberOfIntrestingPopedLogs(){
	NumberOfIntrestingPopedLogs++;
}

void PrintLogStats(){
    Printf("stat::pushed_logs:              %zd\n", NumberOfPushedLogs);
    Printf("stat::HEAD:                     %zd\n", *HEAD);
    Printf("stat::poped_logs:               %zd\n", NumberOfPopedLogs);
    Printf("stat::intresting_poped_logs:    %zd\n", NumberOfIntrestingPopedLogs);
    for(int i=0; i<TOTAL; i++) {
    Printf("stat::poped_logs from %d:       %zd\n", i, TAILS[i]);
    }
}

//Flush out all the stale test cases from the instance id by force
void FlushLog(int id) {

}

//Destroy the test case log owned by the instance id
//The log is eventually destroyed by the fuzzer (close_log())
//when fuzzing ends.
void CloseLog(int id) {
    shmdt(MyLog);
    for(int i=0;i<TOTAL;i++){
	if(i==ID) continue;
    	shmdt(NeighborLog[i]);
    }

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
/*
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
*/
