/*
 * Word count application with one process per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright © 2019 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "word_count.h"
#include "word_helpers.h"

/*
 * Read stream of counts and accumulate globally.
 */
void merge_counts(word_count_list_t *wclist, FILE *count_stream) {
    char *word;
    int count;
    int rv;
    while ((rv = fscanf(count_stream, "%8d\t%ms\n", &count, &word)) == 2) {
        add_word_with_count(wclist, word, count);
    }
    if ((rv == EOF) && (feof(count_stream) == 0)) {
        perror("could not read counts");
    } else if (rv != EOF) {
        fprintf(stderr, "read ill-formed count (matched %d)\n", rv);
    }
}

/*
 * main - handle command line, spawning one process per file.
 */
int main(int argc, char *argv[]) {
    /* Create the empty data structure. */
    word_count_list_t word_counts;
    init_words(&word_counts);

    if (argc <= 1) {
        /* Process stdin in a single process. */
        count_words(&word_counts, stdin);
    } else {
        /* TODO */
        int num_files = argc - 1;
        int pipes[num_files][2];
        pid_t pids[num_files];

        for (int i = 0; i < num_files; i++) {
            if (pipe(pipes[i]) == -1) {
                perror("pipe");
                exit(1);
            }

            pid_t pid = fork();
            if (pid == 0) {
                close(pipes[i][0]);
                dup2(pipes[i][1], STDOUT_FILENO);
                close(pipes[i][1]); 
                word_count_list_t child_word_counts;
                init_words(&child_word_counts);

                FILE *infile = fopen(argv[i + 1], "r");
                if (infile == NULL) {
                    perror("fopen");
                    exit(1);
                }

                count_words(&child_word_counts, infile);
                fclose(infile);

                fprint_words(&child_word_counts, stdout); 
                exit(0);
            } else {
                // parent process
                pids[i] = pid;
                close(pipes[i][1]);
            }
        }

        for (int i = 0; i < num_files; i++) {
            FILE *stream = fdopen(pipes[i][0], "r");
            if (!stream) {
                perror("fdopen");
                exit(1);
            }

            merge_counts(&word_counts, stream);
            fclose(stream);
        }

        for (int i = 0; i < num_files; i++) {
            int status;
            waitpid(pids[i], &status, 0);
        }
    }

    /* Output final result of all process' work. */
    wordcount_sort(&word_counts, less_count);
    fprint_words(&word_counts, stdout);
    return 0;
}
