#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function
 * parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens *tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
    cmd_fun_t *fun;
    char *cmd;
    char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print working directory"},
    {cmd_cd, "cd", "change current working directory"}
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens *tokens) {
    for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
        printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
    }
    return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens *tokens) {
    exit(0);
}

/* Prints current working directory */
int cmd_pwd(unused struct tokens *tokens) {
    char cwd[4096]; 
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        perror("pwd"); 
    }
    return 1;
}

/* Navigate to directory */
int cmd_cd(unused struct tokens *tokens) {
    char *path = tokens_get_token(tokens, 1);
    if (chdir(path) != 0) {
        perror("cd");
    }
    return 1;
}

/* Looks up the built-in command, if it exists. */
int lookup(char *cmd) {
    if (cmd != NULL) {
        for (int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
            if (strcmp(cmd_table[i].cmd, cmd) == 0) {
                return i;
            }
        }
    }
    return -1;
}

/* Intialization procedures for this shell */
void init_shell() {
    /* Our shell is connected to standard input. */
    shell_terminal = STDIN_FILENO;

    /* Check if we are running interactively */
    shell_is_interactive = isatty(shell_terminal);

    if (shell_is_interactive) {
        /* If the shell is not currently in the foreground, we must pause the
         * shell until it becomes a foreground process. We use SIGTTIN to pause
         * the shell. When the shell gets moved to the foreground, we'll receive
         * a SIGCONT. */
        while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp())) {
            kill(-shell_pgid, SIGTTIN);
        }

        /* Saves the shell's process id */
        shell_pgid = getpid();

        /* Take control of the terminal */
        tcsetpgrp(shell_terminal, shell_pgid);
        setpgid(shell_pgid,shell_pgid);
        /* Save the current termios to a variable, so it can be restored later.
         */
        tcgetattr(shell_terminal, &shell_tmodes);
        signal(SIGINT, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);
        signal(SIGKILL, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
    }
}

int main(unused int argc, unused char *argv[]) {
    init_shell();
    static char line[4096];
    int line_num = 0;

    /* Only print shell prompts when standard input is not a tty */
    if (shell_is_interactive) {
        fprintf(stdout, "%d: ", line_num);
    }

    while (fgets(line, 4096, stdin)) {
        /* Split our line into words. */
        struct tokens *tokens = tokenize(line);

        /* Find which built-in function to run. */
        int fundex = lookup(tokens_get_token(tokens, 0));

        if (fundex >= 0) {
            cmd_table[fundex].fun(tokens);
        } else {
            
            size_t argc = tokens_get_length(tokens);
            char *input_file = NULL;
            char *output_file = NULL;
        
            for (size_t i = 0; i < argc; i++) {
                char *token = tokens_get_token(tokens, i);
                if (strcmp(token, "<") == 0 && i + 1 < argc) {
                    input_file = tokens_get_token(tokens, i + 1);
                } else if (strcmp(token, ">") == 0 && i + 1 < argc) {
                    output_file = tokens_get_token(tokens, i + 1);
                }
            }
        
            pid_t pid = fork();
            setpgid(pid, pid);
            tcsetpgrp(STDIN_FILENO, pid);
            if (pid == 0) {
                signal(SIGINT, SIG_DFL);
                signal(SIGTSTP, SIG_DFL);

                char **argv = malloc((argc + 1) * sizeof(char *));
                int j = 0;
                for (size_t i = 0; i < argc; i++) {
                    char *token = tokens_get_token(tokens, i);
                    if ((strcmp(token, "<") == 0 || strcmp(token, ">") == 0) && i + 1 < argc) {
                        i++;
                        continue;
                    }
                    argv[j++] = token;
                }
                argv[j] = NULL;
        
                // redirect input
                if (input_file != NULL) {
                    int fd = open(input_file, O_RDONLY);
                    if (fd < 0) {
                        perror("open input");
                        exit(1);
                    }
                    dup2(fd, STDIN_FILENO);
                    close(fd);
                }
        
                // redirect output
                if (output_file != NULL) {
                    int fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd < 0) {
                        perror("open output");
                        exit(1);
                    }
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }
        
                // path resolution stuff
                char *cmd = argv[0];
                char *path_env = getenv("PATH");
                char full_path[1024];
                char *path = strdup(path_env);
                char *dir = strtok(path, ":");
        
                while (dir != NULL) {
                    snprintf(full_path, sizeof(full_path), "%s/%s", dir, cmd);
                    if (access(full_path, X_OK) == 0) {
                        execv(full_path, argv);
                    }
                    dir = strtok(NULL, ":");
                }
        
                free(path);
                execv(cmd, argv);
                perror("execv");
                free(argv);
                exit(1);

            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
                tcsetpgrp(STDIN_FILENO, shell_pgid);
            }
        }

        if (shell_is_interactive) {
            /* Only print shell prompts when standard input is not a tty. */
            fprintf(stdout, "%d: ", ++line_num);
        }

        /* Clean up memory. */
        tokens_destroy(tokens);
    }

    return 0;
}
