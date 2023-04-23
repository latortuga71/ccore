#include <stdio.h>
#define _GNU_SOURCE
#include <sys/uio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <regex.h>

// #TODO 
// MOVE DEFINITIONS INTO HEADER FILES
//
// #TODO
// USE FPRINTF WITH ERROR CODES INSTEAD OF PERROR
//
// #TODO
// CHECK IF CALLOC DOESNT ERROR OUT

// #TODO
// DEBUG PRINT FUNCTION


void match_regex(){
	regex_t regex;
	int reti;
	char msgbuf[100];

	/* Compile regular expression */
	reti = regcomp(&regex, "^a[[:alnum:]]", 0);
	if (reti) {
	    fprintf(stderr, "Could not compile regex\n");
	    exit(1);
	}

	/* Execute regular expression */
	reti = regexec(&regex, "abc", 0, NULL, 0);
	if (!reti) {
	    puts("Match");
	}
	else if (reti == REG_NOMATCH) {
	    puts("No match");
	}
	else {
	    regerror(reti, &regex, msgbuf, sizeof(msgbuf));
	    fprintf(stderr, "Regex match failed: %s\n", msgbuf);
	    exit(1);
	}

	/* Free memory allocated to the pattern buffer by regcomp() */
	regfree(&regex);
}

typedef struct {
	uint8_t readable;
	uint8_t writable;
	uint8_t executable;
} permissions_t;

typedef struct {
	uint64_t offset_start;
	uint64_t offset_end;
} offset_t;

typedef struct {
	char* name;
	int name_length;
	offset_t* offsets;
	permissions_t* perms;
} memory_region_t;

permissions_t* new_permissions(){
	return calloc(1,sizeof(permissions_t));
}

offset_t* new_offset(){
	return calloc(1,sizeof(offset_t));
}

memory_region_t* new_memory_region(){
	return calloc(1,sizeof(memory_region_t));
}

int dump_memory_region(memory_region_t* region,pid_t pid, FILE* dump_fd);

void free_memory_region(memory_region_t* region){
	if (region->offsets != NULL)
		free(region->offsets);
	if (region->perms != NULL)
		free(region->perms);
	free(region->name);
	free(region);
}

void print_memory_region(memory_region_t* region){
	printf("%s ",region->name);
	printf("%"PRIx64 "-", region->offsets->offset_start);
	printf("%"PRIx64 " ", region->offsets->offset_end);
	printf("%s",region->perms->readable > 0 ?"r":"-");
	printf("%s",region->perms->writable > 0 ?"w":"-");
	printf("%s",region->perms->executable > 0 ?"x":"-");
	printf("\n");
}

int parse_offset(offset_t* offsets,char* address_line){
	long unsigned start, end;
	char* start_address = strtok(address_line, "-");
	if (start_address == NULL){
		perror("Failed to parse region start address");
		return -1;
	}
	// check if null
	char* end_address = strtok(NULL,"-");
	if (end_address == NULL){
		perror("Failed to parse region end address");
		return -1;
	}
	//printf("START %s\n",start_address);
	//printf("END %s\n",end_address);
	start = strtoul(start_address, NULL, 16);
	if (start == 0){
		perror("Failed to parse region start address");
		return -1;
	}
	end = strtoul(end_address, NULL, 16);
	if (start == 0){
		perror("Failed to parse region start address");
		return -1;
	}
	offsets->offset_start = start;
	offsets->offset_end = end;
	return 0;
}

int parse_permissions(permissions_t* perms,char* perm){
	char read,write,exec;
	if (strlen(perm) < 2) {
		perror("permissions string invalid length");
		return -1;
	}
	read = *perm++;
	write = *perm++;
	exec = *perm++;
	if (read != '-')
		perms->readable = 1;
	if (write != '-')
		perms->writable = 1;
	if (exec != '-')
		perms->executable = 1;
	return 0;
}

int skip_region(char* line){
	if (strstr(line, "vsyscall") != NULL) {
		return 1;
	}
	if (strstr(line, "vdso") != NULL) {
		return 1;
	}
	if (strstr(line, "vvar") != NULL) {
		return 1;
	}
	return 0;
}

void parse_region_name(char* name,memory_region_t* region){
	int region_name_len = strlen(name);
	if (region_name_len == 1){
		int len = strlen("anonymous");
		region->name = calloc(len,sizeof(char));
		strncpy(region->name,"anonymous",len);
		region->name_length = len;
		strtok(region->name, "\n");
		return;
	}
	region->name = calloc(region_name_len,sizeof(char));
	region->name_length = region_name_len;
	strncpy(region->name,name,region_name_len);
	strtok(region->name, "\n");
	return;
}

int dump_regions(FILE* maps_file,char* dump_name, long pid){
	size_t len;
	ssize_t read;
	char* line = NULL;
	char* line_og = NULL;
	char* last = NULL;
	FILE* dump_file = fopen(dump_name,"a");
	if (dump_file == NULL) {
		perror("failed to create dump file");
		exit(-1);
	}
	/// each line is a region
	while ((read = getline(&line, &len, maps_file)) != -1) {
		if (skip_region(line)){
			continue;
		}
		memory_region_t* region = new_memory_region();
		offset_t* offset = new_offset();
		permissions_t* perms = new_permissions();
		line_og = line;
		//printf("Retrieved line of length %zu:\n", read);
		//printf("%s", line);
		char* token = strtok_r(line, " ",&line_og);
		// get the offsets its the first token
		if (parse_offset(offset,token) != 0){
			return -1; 
		}
		// get the permissions
		token = strtok_r(NULL," ",&line_og);
		if (token == NULL){
			perror("Failed to parse permissions");
			return -1;
		}
		if (parse_permissions(perms,token) != 0){
			return -1;
		}
		// loop through the rest of the token until you get to the end.
		// the last one should be a string either a path to a binary or name of region 
		// but sometimes they arent named so we need to check if its a number
		while( token != NULL ) {
		  //printf("%s\n", token );
		  last = token;
		  token = strtok_r(NULL, " ",&line_og);
		}
		parse_region_name(last,region);
		region->offsets = offset;
		region->perms = perms;
		print_memory_region(region);
		dump_memory_region(region,pid,dump_file);
		free_memory_region(region);
	}
	free(line);
	fclose(dump_file);
	return 0;
}


int dump_memory_region(memory_region_t* region,pid_t pid, FILE* dump_fd){
	   struct iovec local[1];
           struct iovec remote[1];
	  // get size of buffer we need
	   uint64_t diff = region->offsets->offset_end - region->offsets->offset_start;
	   char* local_buffer = calloc(diff,sizeof(char));
           ssize_t nread;
           local[0].iov_base = local_buffer;
           local[0].iov_len = diff;
           remote[0].iov_base = (void *) region->offsets->offset_start;
           remote[0].iov_len = diff;
           nread = process_vm_readv(pid, local, 1, remote, 1, 0);
           if (nread != diff) {
		free(local_buffer);
		perror("failed to read process memory");
               return 1;
	   }
	   printf("Read %zd bytes from region %s\n",nread,region->name);
	   fwrite(local_buffer,sizeof(char),nread,dump_fd);
	   free(local_buffer);
           return 0;
}


//https://blog.cloudflare.com/diving-into-proc-pid-mem/

int main(int argc, char** argv){
	if (argc < 2) {
		fprintf(stderr,"usage: %s <pid>\n",argv[0]);
		return -1;
	}
	long pid = strtol(argv[1],NULL,0);
	if (pid == 0){
		fprintf(stderr,"failed to parse pid\n");
		return -1;
	}
	printf("%ld\n",pid);
	// # TODO MAKE THIS BUFFER DYNAMIC
	char maps_buffer[20];
	sprintf(maps_buffer,"/proc/%s/maps",argv[1]);
	printf("\n%s\n",maps_buffer);
	FILE* maps_file = fopen(maps_buffer,"r");
	if (maps_file == NULL){
		perror("Failed to open maps file");
		return 0;
	}
	//# TODO add sprintf to add pid to file name
	dump_regions(maps_file,"dump.core",pid);
	fclose(maps_file);
	return 0;
}
