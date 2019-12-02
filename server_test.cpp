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

#include <time.h>

//#include "my_smt_lib2.h"

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

FILE *fp_log = NULL;
FILE *fp_log_read = NULL;

char *trim(char **c)
{//leaky
  if(c == NULL){ 
    #ifdef _SMT_LIB2_
    _MAKE_SYMBOL_TMPL1_("c", TYPE_PTR, true, 
		      "(assert (= %s_%d #x00000000))")
    #endif
    return NULL; 
  }
  //std::cerr << "size is " << strlen(*c) << std::endl;;
#ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("c", TYPE_PTR, true, 
		      "(assert (not (= %s_%d #x00000000)))")
#endif
  
  char *p = (char *)malloc(strlen(*c));
  char *ptr = p;
  while( **c != '\0' )
    {
      #ifdef _SMT_LIB2_
      _MAKE_SYMBOL_TMPL1_("**c", TYPE_CHAR, true, 
			  "(assert (distinct %s_%d #x00))")
      #endif
      if( **c == '\n' ){
	#ifdef _SMT_LIB2_
	_MAKE_SYMBOL_TMPL1_("**c", TYPE_CHAR, false, 
			    "(assert (= %s_%d #x0A))")
	#endif
	*ptr = '\0'; 
      }
      else{ 
	#ifdef _SMT_LIB2_
	_MAKE_SYMBOL_TMPL1_("**c", TYPE_CHAR, false, 
			    "(assert (not (= %s_%d #x0A)))")
	#endif
	*ptr = **c; 
      }
      ptr++;
      (*c)++;
    }
  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("**c", TYPE_CHAR, true,
		      "(assert (not (distinct %s_%d #x00)))")
  #endif
  return p;
}

void log_write(const char *prefix, const char *suffix,  const char *msg)
{
  time_t tm = time(NULL);
  char *c = ctime(&tm);
  char *p = trim(&c);

  fprintf(fp_log, "%s%s: %s %s", 
	  prefix, p, suffix, msg);
  fflush(fp_log);

  //free(p);
  return;
}

void log_init()
{
  if( (fp_log = fopen("log.out", "a+")) == NULL )
    { std::cerr << "Failed: open log." << std::endl;}
  
  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("fp_log", TYPE_PTR, true, 
		      "(assert (not (= %s_%d #x00000000)))")
  #endif

  log_write("\n\n", "start server", "\n");

  return;
}

void log_read_init()
{
  if( (fp_log_read = fopen("log.out", "r+")) == NULL )
    { std::cerr << "Failed: open log." << std::endl;}

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("fp_log_read", TYPE_PTR, true, 
		      "(assert (not (= %s_%d #x00000000)))")
  #endif

   std::cerr << ftell(fp_log) << " " << ftell(fp_log_read) << std::endl; 
}

void log_fini()
{
  std::cerr << ftell(fp_log) << " " << ftell(fp_log_read) << std::endl; 
  fclose(fp_log);
  fclose(fp_log_read);
  return;
}

const char *msg = "Hello!\nGood-bye!\n";

int server_socket_init(s_info *info)
{

  if((info->sd = socket(AF_INET, SOCK_STREAM, 0) ) == -1 )
    { perror("socket");  exit(1); }

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("info->sd", TYPE_INT, true, 
		      "(assert (not (= %s_%d -1)))")
  #endif
   
  info->opt = 1;
  if( setsockopt(info->sd, 
		 SOL_SOCKET, 
		 SO_REUSEADDR, 
		 &(info->opt), 
		 sizeof(info->opt)) == -1 )
    { perror("setsockopt"); exit(1); }

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("setsockopt", TYPE_INT, true, 
		      "(assert (not (= %s_%d -1)))")
  #endif
  
  
  memset(&(info->sv_addr), 0, sizeof(info->sv_addr));
  //sa.sin_len = sizeof(sa);
  info->sv_addr.sin_family = AF_INET;
  info->sv_addr.sin_port = htons(SERVER_PORT);//host to network short
  info->sv_addr.sin_addr.s_addr = htonl(INADDR_ANY);//host to network long
  
  if( bind(info->sd, 
	   (struct sockaddr *)&(info->sv_addr), 
	   sizeof(info->sv_addr)) == -1 )
    { perror("bind"); exit(1); }

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("bind", TYPE_INT, true, 
    "(assert (not (= %s_%d -1)))")
  #endif

  if( listen(info->sd, NQUEUESIZE) )
    { perror("listen"); exit(1); }

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("listen", TYPE_INT, true, 
    "(assert (not (distinct %s_%d 0)))")
  #endif

  std::cerr << "Ready." << std::endl;
  
  return 0;
}

#define PREFIX_CL "Client>"
int user_no = 1;

int interact_client(s_info *info)
{
  int ws, w_size, r_size, recv_size, send_size;

  struct sockaddr_in ca;
  socklen_t ca_len;
  char message[1024];
  char recv_buf[1024];
  char send_buf[1024];

  std::cerr << "Waiting for a connection ... " << std::endl;
  ca_len = sizeof(ca);
  
  if( (ws = accept(info->sd, (struct sockaddr *)&ca, &ca_len)) == -1 )
    { perror("accept"); exit(1); }//wait connecting from client
  std::cerr << "Connected." << std::endl;

  #ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("ws", TYPE_INT, true, 
    "(assert (not (= %s_%d -1)))")
  #endif
  
  pid_t pid;
  

  if( (pid = fork()) == 0 )
    {
#ifdef _SMT_LIB2_
  _MAKE_SYMBOL_TMPL1_("pid", TYPE_INT, true, 
    "(assert (= %s_%d 0))")
#endif


      close(info->sd);
      unsigned int comment_counter = 0;
      unsigned int malloc_size_1 = strlen("Client n>") + 1;
      unsigned int malloc_size_2 = strlen("[Client n joined.]\n") + 1;
      unsigned int malloc_size_3 = strlen("[Client n disjoined.]\n") + 1;
      char *cl = (char *)calloc((malloc_size_3 > malloc_size_2)? 
				malloc_size_3: 
				(malloc_size_2 > malloc_size_1)?
				malloc_size_2:
				malloc_size_1, 
				sizeof(char));

      snprintf(cl, malloc_size_2, "[Client %d joined.]\n", user_no);
      
      log_write("", "", cl);
      
      memset(cl, 0, malloc_size_2);
      snprintf(cl, malloc_size_1, "Client %d>", user_no);

      log_read_init();
  
      while(1)
	{
#ifdef _SMT_LIB2_
	  log_write_smt2("", "(assert (1 > 0))", "");
#endif


#define SYNC1 "send done."
#define SYNC2 "next come."
#define SYNC3 "timeout."
	  while( ftell(fp_log_read) < ftell(fp_log) )
	    {//log load
	      //char buf_log[1024];
#ifdef _SMT_LIB2_
	      _MAKE_SYMBOL_TMPL2_(
				  "ftell1", TYPE_INT, true,
				  "ftell2", TYPE_INT, true,
				  "(assert (< %s_%d %s_%d))")
#endif
		fgets(send_buf, 1024, fp_log_read);//read point
	      char *p = &send_buf[0];
	      std::cout << trim(&p) << std::endl;
	      
	      if( (send_size = send(ws, send_buf, strlen(send_buf), 0)) == -1 )
		{ perror("send"); exit(1);}
#ifdef _SMT_LIB2_
	      _MAKE_SYMBOL_TMPL1_("send_size", TYPE_INT, true,
				  "(assert (not (= %s_%d -1)))")
#endif
		recv(ws, recv_buf, sizeof(recv_buf), 0);//sync 1
	      //sleep(1);
	    }
	  
	  std::cout << SYNC1 << " user No." << user_no << std::endl;
	  if( (send_size = send(ws, SYNC1, strlen(SYNC1), 0)) == -1 )
	    { perror("send"); exit(1);}//sync 0
	  
#ifdef _SMT_LIB2_
	  _MAKE_SYMBOL_TMPL1("send_size", TYPE_INT, true,
			     "(assert (not (= %s_%d -1)))")
#endif
	    
	    ++comment_counter;
	  memset(recv_buf, 0, sizeof(recv_buf));//init buf
	  if( (recv_size = recv(ws, 
				recv_buf, 
				sizeof(recv_buf), 
				0 )) == -1 )
	    { perror("recv"); exit(1); }//sync 1
	  //buffering meg in recv_buf
	  
	  #ifdef _SMT_LIB2_
	  _MAKE_SYMBOL_TMPL1_("recv_size", TYPE_INT, true,
	    "(assert (not (= %s_%d -1)))")
	  #endif

	  if(comment_counter > 0)
	    {//print msg to server and logging
#ifdef _SMT_LIB2_
	      _MAKE_SYMBOL_TMPL1_("comment_counter", TYPE_INT, true,
				  "(assert (> %s_%d 0))")
#endif
		
		if( strncmp(recv_buf, "\n", 1) == 0)
		  {
		    
		    
		    fseek(fp_log, 0L, SEEK_END);
		  }
		else if( strncmp(recv_buf, SYNC3, strlen(SYNC3)) == 0 )
		  {
		    fseek(fp_log, 0L, SEEK_END);
		  }
		else
		  {
		    fprintf(stderr, "Cleint %d> %s", user_no, recv_buf);
		    
		    log_write("", cl, recv_buf);//leak!
		  }
	      
#define MSG1 ":q"	      
	      if( strncmp(recv_buf, MSG1, strlen(MSG1)) == 0 )
		{ //escape
		  fprintf(stderr, "disconnect from client %d ...\n", user_no); 
		  
		  memset(cl, 0, malloc_size_3);
		  snprintf(cl, malloc_size_3, 
			   "[Client %d disjoined.]\n", user_no);
		  log_write("", "", cl);
		  
		  free(cl);
		  break; 
		}
#define MSG2 ":leak"
	      else if( strncmp(recv_buf, MSG2, strlen(MSG2) ) == 0 )
		{
		  fprintf(stderr, "LEAK OCCUR! by user %d.\n", user_no);
		  malloc(1024*1024);
		}

	    }

	}
#ifdef _SMT_LIB2_
      log_write_smt2("", "(assert (not (1 > 0)))", "");
#endif

      std::cerr << ftell(fp_log) << " " << ftell(fp_log_read) << std::endl; 
      close(ws);
      exit(0);
    }

#ifdef _SMT_LIB2_
//_MAKE_SYMBOL_TMPL1_("pid", TYPE_INT, true, 
//    "(assert (not (= %s_%d 0)))")
    fclose(fp_smt);
#endif

  user_no++;
  return 0;
}

int wait_client(s_info *info)
{
  while( user_no < 5 )//
    {
      
      interact_client(info);
    }

  return 0;
}

int server_socket_fini(s_info *info)
{
  if( (shutdown(info->sd, SHUT_RDWR)) == -1 )
    { perror("shutdown"); exit(1); }
  
  if( (close(info->sd)) == -1 )
    { perror("close"); exit(1); }

  return 0;
}

int main(int argc, char *argv[])
{
  s_info info;
  
#ifdef _SMT_LIB2_
  smt_lib2_log_init();
#endif

  server_socket_init(&info);
  log_init();

  wait_client(&info);
  
  //interact_client(&info);
  
  server_socket_fini(&info);
  log_fini();

#ifdef _SMT_LIB2_
  smt_lib2_log_fini();
#endif

  return 0;
}
