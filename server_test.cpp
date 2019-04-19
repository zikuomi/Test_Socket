#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <string>
//#include <fstream>


#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <errno.h>

#define SERVER_PORT 80
#define SERVER_ADDR "127.0.0.1"

//using namespace std;

enum {
  NQUEUESIZE = 5,
};

typedef struct server_info
{
  unsigned short sv_port;

  int sd;
  int opt;
  struct sockaddr_in sv_addr;
} s_info;


const char *msg = "Hello!\nGood-bye!\n";

int init_server(){ return 0; }
int fini_server(){ return 0; }
int get_loop(){ return 0; }

int server_socket_init(s_info *info)
{

  if((info->sd = socket(AF_INET, SOCK_STREAM, 0) ) == -1 )
    { perror("socket");  exit(1); }
   
  info->opt = 1;
  if( setsockopt(info->sd, 
		 SOL_SOCKET, 
		 SO_REUSEADDR, 
		 &(info->opt), 
		 sizeof(info->opt)) == -1 )
    { perror("setsockopt"); exit(1); }
  
  
  memset(&(info->sv_addr), 0, sizeof(info->sv_addr));
  //sa.sin_len = sizeof(sa);
  info->sv_addr.sin_family = AF_INET;
  info->sv_addr.sin_port = htons(SERVER_PORT);//host to network short
  info->sv_addr.sin_addr.s_addr = htonl(INADDR_ANY);//host to network long
  
  if( bind(info->sd, 
	   (struct sockaddr *)&(info->sv_addr), 
	   sizeof(info->sv_addr)) == -1 )
    { perror("bind"); exit(1); }

  if( listen(info.sd, NQUEUESIZE) )
    { perror("listen"); exit(1); }

  std::cerr << "Ready." << std::endl;
  
  return 0;
}

#define PREFIX_CL "Client>"

int interact_client(s_info *info)
{
  int ws, w_size, r_size, recv_size, send_size;
  struct sockaddr_in ca;
  socklen_t ca_len;
  char message[1024];
  char recv_buf[32];
  char send_buf[32];

  while(1)
    {
      std::cerr << "Waiting for a connection ... " << std::endl;
      ca_len = sizeof(ca);
      
      if( (ws = accept(s, (struct sockaddr *)&ca, &ca_len)) == -1 )
	{ perror("accept"); exit(1); }
      
      if( (recv_size = recv(info->sd, recv_buf, sizeof(recv_buf), 0 )) > 0 )
	{ perror("recv"); exit(1); }//sync 1

      while( (r_size = read(info->sd, message, sizeof(message)) ) > 0 )
	{ }

      //std::cerr << "Sneding the message ..." << std::endl;

      if( (w_size = write(ws, msg, strlen(msg))) == -1 )
	{ perror("write"); exit(1); }
      std::cerr << "Message send." << std::endl;

      
    }

   return 0;
}

int server_socket_fini(s_info *info)
{
  if( (shutdown(ws, SHUT_RDWR)) == -1 )
    { perror("shutdown"); exit(1); }
  
  if( (close(ws)) == -1 )
    { perror("close"); exit(1); }

  return 0;
}

int main(int argc, char *argv[])
{
  s_info info;
  
  server_socket_init(&info);

  interact_client(&info);
  
  server_socket_fini(&info);

  return 0;
}
