#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
main()

{
int fd = open("test_100KB_NULL.capsule", O_RDONLY);
/*FILE *fp;
char *encrypted_data1;
int encrypted_len1;
fp = fopen("test_100KB_NULL.capsule", "rb");
   
    fseek(fp, 0, SEEK_END);
    encrypted_len1 = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    encrypted_data1 = malloc(encrypted_len1 + 1);
    fread(encrypted_data1, encrypted_len1, 1, fp);
    fclose(fp);

    encrypted_data1[encrypted_len1] = '\0';*/



int len = lseek(fd,0,SEEK_END);
char *contents = (char *) malloc(len);
printf("len = %d\n",len);
lseek(fd,0,SEEK_SET);
int num_read = read(fd,contents,len);

fwrite(contents,1,len,stdout);
printf("the number of characters read are %d",len); 

}

