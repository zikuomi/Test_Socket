#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <fstream>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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


int init_client(){ return 0; }
int fini_client(){ return 0; }

int client_socket_init(c_info *info)
{
  
  if( (info->sd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    { perror("socket"); exit(1); }

  memset(&(info->sv_addr), 0, sizeof(info->sv_addr));
  info->sv_addr.sin_family = AF_INET;
  info->sv_addr.sin_port = htons(SERVER_PORT);
  info->sv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

  std::cerr << "Connecting to the server ..." << std::endl;
  if( connect(info.sd, 
	      (struct sockaddr *)&(info.sv_addr), 
	      sizeof(info.sv_addr)) == -1 )
    { perror("connect"); exit(1); }
  std::cerr << "Connected." << std::endl;
  
  return 0;
}

int interact_server(c_info *info)
{
  int cc;
  char buf_recv[BUF_SIZE];
  char buf_send[BUF_SIZE];

  while(1)
    {
      while( (cc = read(info->sd, buf_recv, sizeof(buf_recv))) > 0 )
	{ write(STDOUT_FILENO, buf_recv, cc); }

      if( cc == -1 )
	{ perror("read"); exit(1); }

      std::cerr << "msg: " << std::endl;
      fgets(buf_send, BUF_SIZE, stdin);

      write(info->sd, buf_send, sizeof(buf_send));
      if(buf_send[0] == 'q' && buf_send[1] == ':')
	{
	  //write(info->sd, buf_send, sizeof(buf_send));
	  break;
	}
      
      if( (send_size = send(info->sd, )) > 0 )

    }
  return 0;
}

int client_socket_fini(c_info *info)
{

  std::cerr << "\n\nFinished interaction." << std::endl;
  if( shutdown(info.sd, SHUT_RDWR) == -1 )
    { perror("shutdown"); exit(1); }

  if( close(info.sd) == -1 )
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
