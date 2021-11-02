#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char ** argv)
{
char *bad ="Bad session key";

if(argc!=3)
{
	printf("Give correct arguments\n");
	printf("a.out FILE_KEYS FILE_TO_BREAK.gpg\n");
	return 1;
}

FILE * KEYS_FD= fopen(argv[1],"r");

/*Change this if you want to try more keys */
char **keys=malloc(sizeof(char *)*100000 );
keys[0] = malloc (sizeof(char  )*512);


int i=0;
while(fgets(keys[i],512,KEYS_FD)!=NULL)
{
	keys[i][strlen(keys[i])-1]='\0';
	i=i+1;
	keys[i]=malloc(sizeof(char)*512);
}

fclose(KEYS_FD);

char * result=malloc(1024);
char * command = malloc(1024);

for (int j=0; j<i ;j++)
{

	FILE * BRUTE_FORCE_KEYS;
	char * command = malloc(1024);
	sprintf (command, "gpg -d --passphrase %s --batch %s 2>&1",keys[j],argv[2]);
	printf("mycommand: %s\n",command);
	BRUTE_FORCE_KEYS= popen(command,"r");
	if(BRUTE_FORCE_KEYS==NULL)
	printf("something went bad\n");

	int gpg=4;
	while(fgets(result,1024,BRUTE_FORCE_KEYS)!=NULL )
	{

		char * ret;
		ret = strstr(result,bad);
		if(gpg %3==0 && ret==NULL)
		{
			printf("Encryption broken, key is:%s\n",keys[j]);
			free(result);
			free(command);
			for(int j=0; j<i; j++)
        			free(keys[j]);

			free(keys);


			return 10;
		}
		gpg=gpg+1;
	}



}
free(result);
free(command);
for(int j=0; j<i; j++)
	free(keys[j]);

free(keys);

printf("Key not found\n");
}
