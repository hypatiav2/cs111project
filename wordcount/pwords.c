/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright (C) 2019 University of California, Berkeley
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
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "word_count.h"
#include "word_helpers.h"

typedef struct {
    word_count_list_t *word_counts;
    FILE *infile;
} thread_arg_t;

void *count_words_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    count_words(targ->word_counts, targ->infile);
    fclose(targ->infile);  
    free(targ); 
    return NULL;
}

int main(int argc, char *argv[]) {
    /* Create the empty data structure. */
    word_count_list_t word_counts;
    init_words(&word_counts);

    pthread_t *threads = NULL;
    int thread_count = 0;

    if (argc <= 1) {
        /* Process stdin in a single thread. */
        count_words(&word_counts, stdin);
    } else {
        
        int i;
        for (i = 1; i < argc; i++) {
            FILE *infile = fopen(argv[i], "r");
            if (infile == NULL) {
                perror("fopen");
                return 1;
            }

            
            thread_arg_t *arg = malloc(sizeof(thread_arg_t));
            if (arg == NULL) {
                perror("malloc");
                return 1;
            }
            arg->word_counts = &word_counts;
            arg->infile = infile;

            
            threads = realloc(threads, sizeof(pthread_t) * (thread_count + 1));
            if (pthread_create(&threads[thread_count], NULL, count_words_thread, arg) != 0) {
                perror("pthread_create");
                return 1;
            }

            thread_count++;
        }

        // wait for threads to finish
        for (int i = 0; i < thread_count; i++) {
            if (pthread_join(threads[i], NULL) != 0) {
                perror("pthread_join");
                return 1;
            }
        }
    }

    /* Output final result of all threads' work. */
    wordcount_sort(&word_counts, less_count);
    fprint_words(&word_counts, stdout);

    /* Free thread resources */
    free(threads);

    return 0;
}