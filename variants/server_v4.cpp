/*
  variant v1
  leak in :tree only
*/

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

#include "strcmp_wrapper.c"

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

volatile void metabo_check_point(){ return; }

char *trim(char **c)
{//leaky
  if(c == NULL){
    return NULL;
  }
  //std::cerr << "size is " << strlen(*c) << std::endl;;

  char *p = (char *)malloc(strlen(*c));//leaky object: after escape, should be freed
  char *ptr = p;
  while( **c != '\0' )
  {
    if( **c == '\n' )
    {
      *ptr = '\0';
    }
    else
    {
      *ptr = **c;
    }
    ptr++;
    (*c)++;
  }
  return p;
}

void leak()
{
  //malloc(1024*1024);
  return;
}

void log_write(const char *prefix, const char *suffix,  const char *msg)
{
  time_t tm = time(NULL);
  char *c = ctime(&tm);
  char *p = trim(&c);

  fprintf(
    fp_log, "%s%s: %s %s",
	  prefix, p, suffix, msg);
  fflush(fp_log);

  //free(p); // leak point !
  free(p);
  return;
}

void log_init()
{
  if( (fp_log = fopen("log.out", "a+")) == NULL )
  { std::cerr << "Failed: open log." << std::endl; }

  log_write("\n\n", "start server", "\n");

  return;
}

void log_read_init()
{
  if( (fp_log_read = fopen("log.out", "r+")) == NULL )
  { std::cerr << "Failed: open log." << std::endl; }

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

  if( listen(info->sd, NQUEUESIZE) )
  { perror("listen"); exit(1); }

  std::cerr << "Ready." << std::endl;

  return 0;
}

#define PREFIX_CL "Client>"
#define SYNC1 "send done."
#define SYNC2 "next come."
#define SYNC3 "timeout."
#define CMD1_1 ":q"
#define CMD1_0 ":quit"
#define CMD2 ":leak"
#define CMD3_1 ":e "
#define CMD3_0 ":echo "
#define CMD4 ":mangle "
#define CMD5 ":demangle "
#define CMD6_0 ":help"
#define CMD6_1 ":h"
#define CMD7 ":tree "
#define LONGCMD ":longlonglonglongMode "
#define CMD8 ":noalloc "

inline bool isLoging( char *recv_buf )
{
  if( strncmp(recv_buf, "\n", strlen("\n")) == 0 ){ return false; }
  //no user msg
  if( strncmp(recv_buf, SYNC3, strlen(SYNC3)) == 0 ){ return false; }
  //timeout (automatic sent MSG from client program)

  return true;
}

inline bool isCommand( char *recv_buf ){ return (recv_buf[0] == ':'); }
inline bool isQuit( char *recv_buf ){ return ( strncmp(recv_buf, CMD1_0, strlen(CMD1_0)) == 0 || strncmp(recv_buf, CMD1_1, strlen(CMD1_1)) == 0); }
inline bool isLeak( char *recv_buf ){ return (strncmp(recv_buf, CMD2, strlen(CMD2)) == 0); }
inline bool isEcho( char *recv_buf ){ return ( strncmp(recv_buf, CMD3_0, strlen(CMD3_0)) == 0 || strncmp(recv_buf, CMD3_1, strlen(CMD3_1)) == 0); }
inline bool isMangle( char *recv_buf ){ return (strncmp(recv_buf, CMD4, strlen(CMD4)) == 0); }
inline bool isDemangle( char *recv_buf ){ return (strncmp(recv_buf, CMD5, strlen(CMD5)) == 0); }
inline bool isHelp( char *recv_buf ){ return ( strncmp(recv_buf, CMD6_0, strlen(CMD6_0)) == 0 || strncmp(recv_buf, CMD6_1, strlen(CMD6_1)) == 0 ); }
inline bool isTree( char *recv_buf ){ return (strncmp(recv_buf, CMD7, strlen(CMD7)) == 0); }
inline bool isLong( char *recv_buf ){ return (strncmp(recv_buf, LONGCMD, strlen(LONGCMD)) == 0); }
inline bool isNoAlloc( char *recv_buf ){ return (strncmp(recv_buf, CMD8, strlen(CMD8)) == 0); }

void error_log( char *cl, const char *err_msg )
{
  log_write("", cl, err_msg);
  return;
}

#define OPT_FLAG_LA 0x01
#define OPT_FLAG_SA 0x02
#define OPT_FLAG_UB 0x04
#define OPT_FLAG_SP 0x08
int log_echo( char *ptr, unsigned char option_flag, char *cl )
{
  unsigned long buf_size = 2*strlen(ptr) + 1;
  char *buf = (char *)calloc(sizeof(char), buf_size);// if option -b or -B -> error handling -> leak

  unsigned int index = 0;
  while( *ptr != '\0' )
  {
    if( (option_flag & OPT_FLAG_LA) > 0 && 'a' <= *ptr && *ptr <= 'z' )
    {
      buf[index++] = (*ptr) - 0x20;
    }
    else if( (option_flag & OPT_FLAG_SA) > 0 && 'A' <= *ptr && *ptr <= 'Z' )
    {
      buf[index++] = (*ptr) + 0x20;
    }
    else
    {
      buf[index++] = *ptr;
    }
    if( buf_size <= index )
    {
      error_log(cl, "ERROR: mode echo: buffer over.\n");
      metabo_check_point();
      return -1;
    }
    /*--------------------------------------------------------------*/
    if( (option_flag & OPT_FLAG_UB) > 0 && *(ptr+1) != '\0' )
    {
      buf[index++] = '_';
    }
    else if( (option_flag & OPT_FLAG_SP) > 0 && *(ptr+1) != '\0' )
    {
      buf[index++] = ' ';
    }

    if( buf_size <= index )
    {
      error_log(cl, "ERROR: mode echo: buffer over.\n");
      metabo_check_point();
      return -1;//leak!
    }

    ptr++;
  }

  log_write("", cl, buf);
  free(buf);//if not reach here, leak occur
  return 0;
}

int parse_option_echo_mode( char *recv_buf, char *cl )
{
  char *ptr = recv_buf;
  while( *ptr != ' ' ){ ptr++; }// slide pointer until reach space (:echo_<- here)
  // *ptr == ' '
  while( *ptr == ' ' ){ ptr++; }// slide pointer until reach option or string or end of buffer
  // *ptr != ' '

  unsigned char option_flag = 0;
  if( *ptr == '-' )
  {//option matching
    unsigned int i = 1;
    while( *(ptr+i) != ' ' && *(ptr+i) != '\0' )
    {
      if( *(ptr+i) == 'A' )
      {
        if( (option_flag & OPT_FLAG_SA) > 0 )
        {//error pattern
          error_log(cl, " ERROR: echo mode: can't use options -a -A at once.\n");
          return -1;
        }
        option_flag |= OPT_FLAG_LA;
      }
      else if( *(ptr+i) == 'a' )
      {
        if( (option_flag & OPT_FLAG_LA) > 0 )
        {//error pattern
          error_log(cl, " ERROR: echo mode: can't use options -a -A at once.\n");
          return -1;
        }
        option_flag |= OPT_FLAG_SA;
      }
      else if( *(ptr+i) == 'b' )
      {
        if( (option_flag & OPT_FLAG_SP) > 0 )
        {//error pattern
          error_log(cl, " ERROR: echo mode: can't use options -b -B at once.\n");
          return -1;
        }
        option_flag |= OPT_FLAG_UB;
      }
      else if( *(ptr+i) == 'B' )
      {
        if( (option_flag & OPT_FLAG_UB) > 0 )
        {//error pattern
          error_log(cl, " ERROR: echo mode: can't use options -b -B at once.\n");
          return -1;
        }
        option_flag |= OPT_FLAG_SP;
      }
      else
      {// unexpected pattern
        error_log(cl, " ERROR: echo mode: can use options -[a|A][b|B] only.\n");
        return -1;
      }

      i++;
    }// while( *(ptr+i) )
    ptr += i; //
  }// if( *ptr == '-' )

  while( *ptr == ' ' ){ ptr++; }// slide pointer until reach option or string or end of buffer

  log_echo(ptr, option_flag, cl);

  return 0;
}

//keywords
#define PRIM_V "void"
#define PRIM_I "int"
#define PRIM_C "char"
#define PRIM_L "long"
#define PRIM_S "short"
#define PRIM_F "float"
#define PRIM_D "double"
#define MODI_U "unsigned"
#define MODI_P "*"

inline unsigned long isPrimitive( char *ptr )
{
  if( strncmp(ptr, PRIM_V, strlen(PRIM_V)) == 0 ){ return strlen(PRIM_V); }
  if( strncmp(ptr, PRIM_I, strlen(PRIM_I)) == 0 ){ return strlen(PRIM_I); }
  if( strncmp(ptr, PRIM_C, strlen(PRIM_C)) == 0 ){ return strlen(PRIM_C); }
  if( strncmp(ptr, PRIM_L, strlen(PRIM_L)) == 0 ){ return strlen(PRIM_L); }
  if( strncmp(ptr, PRIM_S, strlen(PRIM_S)) == 0 ){ return strlen(PRIM_S); }
  if( strncmp(ptr, PRIM_F, strlen(PRIM_F)) == 0 ){ return strlen(PRIM_F); }
  if( strncmp(ptr, PRIM_D, strlen(PRIM_D)) == 0 ){ return strlen(PRIM_D); }
  return 0;
}

int parse_mangle_mode( char *recv_buf, char *cl )
{
  char *ptr = recv_buf;
  char *function_name = (char *)malloc(sizeof(char) * 32);
  char *function_args = (char *)malloc(sizeof(char) * 32);
  unsigned int buf_size = 1024;
  char *buf = (char *)malloc(sizeof(char) * buf_size);

  while( *ptr != ' ' ){ ptr++; }// slide pointer until reach space (:mangle_<- here)
  // *ptr == ' '
  while( *ptr == ' ' ){ ptr++; }// slide pointer until reach option or string or end of buffer
  // *ptr != ' '

  // check return type (unsigned exist ?)
  if( strncmp(ptr, MODI_U, strlen(MODI_U)) == 0 )
  {
    ptr += strlen(MODI_U);
    while( *ptr == ' ' ){ ptr++; }
  }

  // check return type
  unsigned long prim_len;
  if( ( prim_len = isPrimitive(ptr) ) > 0 )
  {
    ptr += prim_len;
  }
  else
  {
    while
    (
      ('0' <= *ptr && *ptr <= '9') ||
      ('a' <= *ptr && *ptr <= 'z') ||
      ('A' <= *ptr && *ptr <= 'Z') ||
      *ptr == '_'
    )
    {
      ptr++;
    }
  }
  if( *ptr != ' ' && *ptr != '*')
  {//error
    error_log(cl, "ERROR! mangle mode: use disable charactor for return type name.\n");
    free(function_name);
    free(function_args);
    free(buf);
    //metabo_check_point();
    return -1;
  }

  // check return type (pointer exist ?)
  while( *ptr == ' ' ){ ptr++; }
  while( *ptr == '*' ){ ptr++; }
  while( *ptr == ' ' ){ ptr++; }

  // check function name
  // enable charactor for function name, '0'-'9', 'a'-'z', 'A'-'Z', '_'
  unsigned int function_name_length = 0;
  while
  (
    ('0' <= *ptr && *ptr <= '9') ||
    ('a' <= *ptr && *ptr <= 'z') ||
    ('A' <= *ptr && *ptr <= 'Z') ||
    *ptr == '_'
  )
  {
    function_name[function_name_length] = *ptr;
    function_name_length++;
    ptr++;
  }
  function_name[function_name_length] = '\0';
  if( *ptr != ' ' && *ptr != '(' )
  {//error
    error_log(cl, "ERROR! mangle mode: use disable charactor for function name.\n");
    free(function_name);
    free(function_args);
    free(buf);
    //metabo_check_point();
    return -1;
  }
  while( *ptr == ' ' ){ ptr++; }

  // checking args
  if( *ptr == '(' )
  {// check args (some args ...)
    ptr++;
    unsigned int index = 0;
    while( *ptr != ')' && *ptr != '\0' )
    {
      while( *ptr == ' ' ){ ptr++; }
      if( (prim_len = isPrimitive(ptr)) > 0 )
      {
        if( strncmp(ptr, PRIM_V, strlen(PRIM_V)) == 0 ){ function_args[index++] = 'v'; }
        else if( strncmp(ptr, PRIM_I, strlen(PRIM_I)) == 0 ){ function_args[index++] = 'i'; }
        else if( strncmp(ptr, PRIM_C, strlen(PRIM_C)) == 0 ){ function_args[index++] = 'c'; }
        else if( strncmp(ptr, PRIM_L, strlen(PRIM_L)) == 0 ){ function_args[index++] = 'l'; }
        else if( strncmp(ptr, PRIM_S, strlen(PRIM_S)) == 0 ){ function_args[index++] = 's'; }
        else if( strncmp(ptr, PRIM_F, strlen(PRIM_F)) == 0 ){ function_args[index++] = 'f'; }
        else if( strncmp(ptr, PRIM_D, strlen(PRIM_D)) == 0 ){ function_args[index++] = 'd'; }
        ptr += prim_len;
      }
      while( *ptr == ' ' ){ ptr++; }

      if( *ptr != ',' && *ptr != ')' )
      {//error
        fprintf(stderr, "disable function args: %c\n", *ptr);
        error_log(cl, "ERROR! mangle mode: use disable charactor in function args.\n");
        free(function_name);
        free(function_args);
        free(buf);
        //metabo_check_point();
        return -1;
      }
      if( *ptr == ',' ){ ptr++; }
    }
    function_args[index] = '\0';
  }
  else
  {//error
    error_log(cl, "ERROR! mangle mode: use disable charactor after function name.\n");
    free(function_name);
    free(function_args);
    free(buf);
    //metabo_check_point();
    return -1;
  }

  // finally
  snprintf(buf, buf_size, "_Z%u%sE%s\n", function_name_length, function_name, function_args);
  log_write("", cl, buf);

  // if not reach here, leak occur
  free(function_name);
  free(function_args);
  free(buf);

  return 0;
}

typedef struct tree
{
  unsigned int id;
  char *name;
  struct tree *child[2]; // 0: left, 1:right
} TREE;
TREE *tree_ptr;

int init_tree(TREE *tree, unsigned int id)
{
  tree->id = id;
  tree->name = (char *)malloc(sizeof(char)*10);
  tree->child[0] = NULL;
  tree->child[1] = NULL;
  return 0;
}

int parse_tree_mode( char *recv_buf, char *cl )
{
  char *ptr = recv_buf;

  while( *ptr != ' ' ){ ptr++; }// slide pointer until reach space (:tree_<- here)
  // *ptr == ' '
  while( *ptr == ' ' ){ ptr++; }// slide pointer until reach option or string or end of buffer
  // *ptr != ' '

  while( *ptr != '\0' && *ptr != '\n' )
  {
    if( strncmp(ptr, "add;", strlen("add;")) == 0 )
    {
      ptr += strlen("add;");
      // lost NULL check if(tree_ptr == NULL)
      tree_ptr = (TREE *)malloc(sizeof(TREE));
      init_tree(tree_ptr, 0);
    }
    else if( strncmp(ptr, "left;", strlen("left;")) == 0 )
    {
      ptr += strlen("left;");
      if( tree_ptr != NULL )
      {
        // lost NULL check if(tree_ptr->child[0] == NULL)
        tree_ptr->child[0] = (TREE *)malloc(sizeof(TREE));
        init_tree(tree_ptr->child[0], 1);
      }
    }
    else if( strncmp(ptr, "right;", strlen("right;")) == 0 )
    {
      ptr += strlen("right;");
      if( tree_ptr != NULL && tree_ptr->child[1] == NULL )
      {
        // lost NULL check if(tree_ptr->child[1] == NULL)
        tree_ptr->child[1] = (TREE *)malloc(sizeof(TREE));
        init_tree(tree_ptr->child[1], 2);
      }
    }
    else
    {
      error_log(cl, "ERROR! tree mode: unexpected pattern.\n");
      // leakage (if tree_ptr != NULL)
      break;
    }
    while( *ptr == ' ' ){ ptr++; }
  }

  if( tree_ptr != NULL )
  {
    if( tree_ptr->child[0] != NULL )
    {
      free( tree_ptr->child[0]->name );
      free( tree_ptr->child[0] );
      //leak (tree_ptr->child[0]->name)
      //metabo_check_point();
    }
    if( tree_ptr->child[1] != NULL )
    {
      free( tree_ptr->child[1] );
      //leak (tree_ptr->child[1]->name)
      metabo_check_point();
    }
    // leakage (if add; add;)
    free( tree_ptr->name );
    free( tree_ptr );
    tree_ptr = NULL;
  }

  metabo_check_point();
  return 0;
}


#define SUB_CMD1 "GET "
#define SUB_CMD2 "http://"
#define SUB_CMD3 "127.0.0.1"
#define SUB_CMD4 ":80"
#define SUB_CMD5 "/test.html"
#define SUB_CMD6 " HTTP/"
#define SUB_CMD7 "1.1"

int parse_long_mode( char *recv_buf, char *cl )
{
  char *ptr = recv_buf;
  ptr += strlen(LONGCMD);

  if( strncmp(ptr, SUB_CMD1, strlen(SUB_CMD1)) == 0 ){
    ptr += strlen(SUB_CMD1);
    if( strncmp(ptr, SUB_CMD2, strlen(SUB_CMD2)) == 0 ){
      ptr += strlen(SUB_CMD2);
      if( strncmp(ptr, SUB_CMD3, strlen(SUB_CMD3)) == 0 ){
        ptr += strlen(SUB_CMD3);
        if( strncmp(ptr, SUB_CMD4, strlen(SUB_CMD4)) == 0 ){
          ptr += strlen(SUB_CMD4);
          if( strncmp(ptr, SUB_CMD5, strlen(SUB_CMD5)) == 0 ){
            ptr += strlen(SUB_CMD5);
            if( strncmp(ptr, SUB_CMD6, strlen(SUB_CMD6)) == 0 ){
              ptr += strlen(SUB_CMD6);
              if( strncmp(ptr, SUB_CMD7, strlen(SUB_CMD7)) == 0 ){
                ptr += strlen(SUB_CMD7);
                fprintf(stdout, "congratulation! leak!");
                leak();
                metabo_check_point();
              }
            }
          }
        }
      }
    }
  }

  return 0;
}

int parse_no_alloc_mode( char *recv_buf, char *cl )
{
  char *ptr = recv_buf;
  while( *ptr != '\0' )
  {
    while( *ptr == '*' ){ ptr++; }
    while( *ptr == '_' ){ ptr++; }
    while( *ptr == ' ' ){ ptr++; }
    while( *ptr == '#' ){ ptr++; }
    while( *ptr == '^' ){ ptr++; }
    if( *ptr == '\0' ){ break; }
    else{ ptr++; }
  }

  return 0;
}

int parse_demangle_mode( char *recv_buf, char *cl )
{

  return 0;
}

int user_no = 1;
#define BUF_SIZE 1024
int interact_client(s_info *info)
{
  int ws, w_size, r_size, recv_size, send_size;

  struct sockaddr_in ca;
  socklen_t ca_len;
  char message[BUF_SIZE];
  char recv_buf[BUF_SIZE];
  char send_buf[BUF_SIZE];

  std::cerr << "Waiting for a connection ... " << std::endl;
  ca_len = sizeof(ca);

  if( (ws = accept(info->sd, (struct sockaddr *)&ca, &ca_len)) == -1 )
  { perror("accept"); exit(1); }//wait connecting from client
  std::cerr << "Connected." << std::endl;

  pid_t pid;

  if( (pid = fork()) == 0 )
  {
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
    /*-----------------------------------------------*/
    /* kokomade outer loop */
    /*-----------------------------------------------*/
    while(1)
    {//input loop
      /*-----------------------------------------------*/
      while( ftell(fp_log_read) < ftell(fp_log) )
      {//log load
        //char buf_log[1024];
        fgets(send_buf, BUF_SIZE, fp_log_read);//read point
        char *p = &send_buf[0];
        p = trim(&p);
        //std::cout << trim(&p) << std::endl;//leak!
        std::cout << p << std::endl;
        free(p);

        if( (send_size = send(ws, send_buf, strlen(send_buf), 0)) == -1 )
        { perror("send"); exit(1); }

        recv(ws, recv_buf, sizeof(recv_buf), 0);//sync 1, not user msg but auto msg
        //sleep(1);
      }
      /*-----------------------------------------------*/
      //std::cout << SYNC1 << " user No." << user_no << std::endl;
      if( (send_size = send(ws, SYNC1, strlen(SYNC1), 0)) == -1 )
      { perror("send"); exit(1); }//sync 0

      ++comment_counter;
      memset(recv_buf, 0, sizeof(recv_buf));//init buf
      if( (recv_size = recv(ws, recv_buf, sizeof(recv_buf), 0 )) == -1 )
      { perror("recv"); exit(1); }//sync 1, user msg: iip start/end
      // buffering msg in recv_buf
      // this is symbolize point

      /*--------------------------------------------------------------*/
      /* for path explosion */
      /* 事実上の入力文字列の長さ判定部分 → n 文字目が\0で固定される */
      /* → ここである程度までループしないと、後半のstrncmpはすべてUNSATになる */
      /*--------------------------------------------------------------*/
      char *ptr_c = recv_buf;
      unsigned int char_len = 0;
      while( *ptr_c != '\0' )
      {
        char_len++;
        ptr_c++;
      }
      //printf("char_len: %u\n", char_len);

      /*--------------------------------------------------------------*/
      /* want to break limit point: (comment_counter > 0) always true */
      /*--------------------------------------------------------------*/
      //if(comment_counter > 0)
      if(1)
      {//print msg to server and logging

        /*--------------------------------------------------------------*/
        /* check to be going to log */
        if( isLoging(recv_buf) )
        {
          fprintf(stderr, "Cleint %d> %s", user_no, recv_buf);
          log_write("", cl, recv_buf);//leak!
        }
        else
        {
          // log will not seeked
          // pattern is "\n" or SYNC3 := "timeout."
          fseek(fp_log, 0L, SEEK_END);
        }
        /*--------------------------------------------------------------*/
        /* pattern match for input (recv_buf)                           */
        /*--------------------------------------------------------------*/
        if( isCommand(recv_buf) )
        {// command pattern check
          if( isQuit(recv_buf) )
          { // :q escape -> want to skip path exploration
            fprintf(stderr, "disconnect from client %d ...\n", user_no);

            memset(cl, 0, malloc_size_3);
            snprintf(cl, malloc_size_3, "[Client %d disjoined.]\n", user_no);
            log_write("", "", cl);//leak! -> not leak(12/18)

            free(cl);
            break;
          }
          else if( isHelp(recv_buf) )
          {
            fprintf(
              stdout,
              "<help>\n"
              ":[e|echo] -[a|A][b|B] [string] -- echo mode.\n"
              ":mangle [return type] [func name]({arg type}, ) -- mangle like c++.\n"
              ":leak -- leak occur!\n"
              ":[h|help] -- print this message.\n"
              ":[q|quit] -- server disconnect.\n");
          }
          else if( isLeak(recv_buf) )
          {
            fprintf(stderr, "LEAK OCCUR! by user %d.\n", user_no);
            leak();
            metabo_check_point();
            log_write("", cl, "LEAK OCCUR ... (((^o^)))");
          }
          else if( isEcho(recv_buf) )
          {
            fprintf(stderr, "echo mode: by user %d.\n", user_no);
            parse_option_echo_mode(recv_buf, cl);
          }
          else if( isMangle(recv_buf) )
          {
            fprintf(stderr, "mangle mode: by user %d.\n", user_no);
            parse_mangle_mode(recv_buf, cl);
          }
          else if( isDemangle(recv_buf) )
          {
            fprintf(stderr, "demangle mode: by user %d.\n", user_no);
            parse_demangle_mode(recv_buf, cl);
          }
          else if( isTree(recv_buf) )
          {
            fprintf(stderr, "tree mode: by user %d.\n", user_no);
            parse_tree_mode(recv_buf, cl);
          }
          else if( isLong(recv_buf) )
          {
            fprintf(stderr, "longlonglonglongMode: by user %d.\n", user_no);
            parse_long_mode(recv_buf, cl);
          }
          else if( isNoAlloc(recv_buf) )
          {
            fprintf(stderr, "no alloc mode: by user %d.\n", user_no);
            parse_no_alloc_mode(recv_buf, cl);
          }
          else
          {
            fprintf(stderr, "unexpected mode: by user %d.\n", user_no);
          }

        }// if( isCommand() )
        /*--------------------------------------------------------------*/
      }// if( comment_counter > 0 )

    }// while(1): input loop
    /*--------------------------------------------------------------*/
    std::cerr << ftell(fp_log) << " " << ftell(fp_log_read) << std::endl;
    close(ws);
    exit(0);
  }

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

  server_socket_init(&info);
  log_init();

  wait_client(&info);

  //interact_client(&info);

  server_socket_fini(&info);
  log_fini();

  return 0;
}
