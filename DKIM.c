#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include<sys/time.h>
long sign(char **inputMessage,char *shaType, char *key, char **output)
{
  struct timeval time_end,time_start;	
	long time_elapsed_sign=0;
	int pid=0;
	gettimeofday(&time_start,NULL);
	for(int i=1;i<=10;i++)
	{
	 pid=fork();
	 if(pid!=0)
	  execlp("openssl","dgst",shaType,"-sign",key,"-out",output[i],inputMessage[i],NULL);
	 else
	 waitpid(pid,NULL,0);
	}
	gettimeofday(&time_end,NULL);
	time_elapsed_sign=(time_end.tv_sec-time_start.tv_sec)*1000000+(time_end.tv_usec-time_start.tv_usec);
	return time_elapsed_sign;
}

long verify(char **inputMessage,char *shaType, char *key, char **output)
{
     struct timeval time_end,time_start;
     long time_elapsed_verify=0;
     int pid=0;
     gettimeofday(&time_start,NULL);
     for(int i=1;i<=10;i++)
    	{	
	 pid=fork();
	 if(pid!=0)
	  execlp("openssl","dgst",shaType,"-verify",key,"-signature",output[i],inputMessage[i],NULL);
	 else
	 waitpid(pid,NULL,0);
	}
	gettimeofday(&time_end,NULL);
	time_elapsed_verify=(time_end.tv_sec-time_start.tv_sec)*1000000+(time_end.tv_usec-time_start.tv_usec);
	return time_elapsed_verify;

}

int main()
{
  char *inputMessage[11];
  char *SHA1Using1024[11];
  char *SHA256Using1024[11];
  char *SHA1Using2048[11];
  char *SHA256Using2048[11];
  
  for(int i=1;i<=10;i++)
  {
  	inputMessage[i]=(char*)malloc(15);
  	SHA1Using1024[i]=(char*)malloc(15);
  	SHA256Using1024[i]=(char*)malloc(15);
  	SHA1Using2048[i]=(char*)malloc(15);
  	SHA256Using2048[i]=(char*)malloc(25);
  	
  	sprintf(inputMessage[i],"Erep/msg%d.txt",i);
  	sprintf(SHA1Using1024[i],"Output/1024SHA1/cipher.%d",i);
  	sprintf(SHA1Using2048[i],"Output/2048SHA1/cipher.%d",i);
  	sprintf(SHA256Using1024[i],"Output/1024SHA256/cipher.%d",i);
  	sprintf(SHA256Using2048[i],"Output/2048SHA256/cipher.%d",i);
  	
  } 
  
  long totalTimeTaken=0;
  for(int i=1;i<=5;i++)
  {
    	totalTimeTaken=0;
	totalTimeTaken=sign(inputMessage,"-sha1","Output/rsaprivatekey1024.pem",SHA1Using1024);
  	printf("SHA1, %d, 1024, %ld\n",i,totalTimeTaken);
  	
	totalTimeTaken=0;
  	totalTimeTaken=sign(inputMessage,"-sha1","Output/rsaprivatekey2048.pem",SHA1Using2048);
  	printf("SHA1, %d, 2048, %ld\n",i,totalTimeTaken);
  	
	totalTimeTaken=0;
  	totalTimeTaken=sign(inputMessage,"-sha256","Output/rsaprivatekey1024.pem",SHA256Using1024);
  	printf("SHA256, %d, 1024, %ld\n",i,totalTimeTaken);
  	
  	totalTimeTaken=0;
	totalTimeTaken=sign(inputMessage,"-sha256","Output/rsaprivatekey2048.pem",SHA256Using2048);
  	printf("SHA256, %d, 2048, %ld\n",i,totalTimeTaken);
	printf("\n");
 } 
 for(int i=1;i<=5;i++) {     
	//Verify 
	totalTimeTaken=0;
	totalTimeTaken=verify(inputMessage,"-sha1","Output/rsapublickey1024.pem",SHA1Using1024);
        printf("Verify-SHA1, %d, 1024, %ld\n",i,totalTimeTaken);

	totalTimeTaken=0;
        totalTimeTaken=verify(inputMessage,"-sha1","Output/rsapublickey2048.pem",SHA1Using2048);
        printf("Verify-SHA1, %d, 2048, %ld\n",i,totalTimeTaken);

	totalTimeTaken=0;
        totalTimeTaken=verify(inputMessage,"-sha256","Output/rsapublickey1024.pem",SHA256Using1024);
        printf("Verify-SHA256, %d, 1024, %ld\n",i,totalTimeTaken);

        totalTimeTaken=0;
	totalTimeTaken=verify(inputMessage,"-sha256","Output/rsapublickey2048.pem",SHA256Using2048);
        printf("Verify-SHA256, %d, 2048, %ld\n",i,totalTimeTaken);
        printf("\n");
 }
         
  return 0;
}
