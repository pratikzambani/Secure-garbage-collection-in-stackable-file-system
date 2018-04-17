#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
//#include<fcntl.h>

#include<errno.h>
#include<sys/ioctl.h>

#include "sgctl.h"

extern int errno ;

int main(int argc, char *argv[])
{
	int c;
    FILE *fp;
	int fd;
	int err;
	char *file_name = NULL;


	// parse file name argument
	while ((c = getopt (argc, (char **)argv, "u:")) != -1)
		switch(c)
		{
			case 'u':
				file_name = optarg;
				break;
			case '?':
				if(optopt == 'u')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
				return 1;
		}

	if(!file_name)
	{
		printf("file name needs to be provided using -u option\n");
		return 0;
	}

	//printf ("file_name = %s\n", file_name);

	fp = fopen(file_name, "r");
    fd = fileno(fp);

    if(fd == -1)
    {
    	printf("unable to open file, exiting...\n");
    	return 0;
    }
	//printf("fd val is %d\n", fd);
	
	err = ioctl(fd, SGFS_IOCTL_RESTORE);
	if(err)
		printf("ioctl operation failed with errno is %d\n", errno);
	//printf("ioctl returned %d\n", err);
	
	fclose(fp);
	return 0;
}
