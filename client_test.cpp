#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>

#include <iostream>
#include <fstream>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <signal.h>

#define SERVER_PORT 80
#define SERVER_ADDR "127.0.0.1"

//using namespace std;

#define BUF_SIZE 1024

typedef struct client_info
{
  unsigned short sv_port;
  char *sv_ip;
  char *msg;

  int sd;//socket discriptor
  struct sockaddr_in sv_addr;
} c_info;


int client_socket_init(c_info *info)
{
  
  if( (info->sd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    { perror("socket"); exit(1); }
  
  memset(&(info->sv_addr), 0, sizeof(info->sv_addr));
  info->sv_addr.sin_family = AF_INET;
  info->sv_addr.sin_port = htons(SERVER_PORT);
  info->sv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
  
  std::cerr << "Connecting to the server ..." << std::endl;
  if( connect(info->sd, 
	      (struct sockaddr *)&(info->sv_addr), 
	      sizeof(info->sv_addr)) == -1 )
    { perror("connect"); exit(1); }
  std::cerr << "Connected." << std::endl;
  
  return 0;
}

int can_recv(int fd)
{
  fd_set fdset;
  struct timeval timeout;
  FD_ZERO( &fdset );
  FD_SET( fd, &fdset );
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  return select(fd+1, &fdset, NULL, NULL, &timeout);
}

int interact_server(c_info *info)
{
  int send_size, recv_size;
  char buf_recv[BUF_SIZE];
  char buf_send[BUF_SIZE];
  char buf_input[BUF_SIZE];
  
  //connected server(info->sd)
#define SYNC1 "send done."
#define SYNC2 "come next."
#define SYNC3 "timeout."
  while(1)
    { //interact loop

      while( (recv_size = recv(info->sd, buf_recv, BUF_SIZE, 0) ) > 0 )
	{//get log
	  if( strncmp(buf_recv, SYNC1, strlen(SYNC1)) == 0 ){ break; }//sync 0
	  send(info->sd, SYNC2, strlen(SYNC2), 0);//sync 1

	  std::cerr << buf_recv;
	  memset(buf_recv, 0, BUF_SIZE);
	 
	  //sleep(1);
	}
      
      //memcpy(buf_input, stdin, BUF_SIZE );
      std::cerr << "msg: " << buf_input;
      if(can_recv(STDIN_FILENO))
	{
	  fgets(buf_send, BUF_SIZE, stdin);
       
	  if( (send_size = send(info->sd, buf_send, strlen(buf_send), 0)) == -1 )
	    { perror("send"); exit(1); }//sync1
	  memset(buf_input, 0, BUF_SIZE);

	  if( strncmp(buf_send, ":q", 2) == 0 )
	    { fprintf(stderr, "disconnect ... \n"); break; }
	}
      else
	{
	  std::cerr << "\r";
	  if( (send_size = send(info->sd, SYNC3, strlen(SYNC3), 0)) == -1 )
	    { perror("send"); exit(1); }//sync1
	}

    }
  return 0;
}

int client_socket_fini(c_info *info)
{

  std::cerr << "\n\nFinished interaction." << std::endl;
  if( shutdown(info->sd, SHUT_RDWR) == -1 )
    { perror("shutdown"); exit(1); }

  if( close(info->sd) == -1 )
    { perror("close"); exit(1); }

  return 0;
}

int main(int argc, char *argv[])
{
  c_info info;

  client_socket_init(&info);

  interact_server(&info);

  client_socket_fini(&info);

  return 0;
}
