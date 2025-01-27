#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define MAX_PATTERNS 10000
#define MAX_LINE_LENGTH 256

// Function to read lines from a file into an array of strings
int read_lines(const char *filename, char lines[][MAX_LINE_LENGTH], int max_lines) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    int count = 0;
    while (count < max_lines && fgets(lines[count], MAX_LINE_LENGTH, file)) {
        // Remove newline character
        size_t len = strlen(lines[count]);
        if (len > 0 && lines[count][len - 1] == '\n') {
            lines[count][len - 1] = '\0';
        }
        count++;
    }

    fclose(file);
    return count;
}

int main() {
    char patterns[MAX_PATTERNS][MAX_LINE_LENGTH];
    char targets[MAX_PATTERNS][MAX_LINE_LENGTH];
    regex_t regex;
    int i;
    int num_patterns, num_targets;

    // Read patterns from file
    num_patterns = read_lines("patterns.txt", patterns, MAX_PATTERNS);
    if (num_patterns < 0) {
        fprintf(stderr, "Failed to read patterns\n");
        return EXIT_FAILURE;
    }

    // Read target strings from file
    num_targets = read_lines("targets.txt", targets, MAX_PATTERNS);
    if (num_targets < 0) {
        fprintf(stderr, "Failed to read targets\n");
        return EXIT_FAILURE;
    }

    // Combine all patterns into a single regex pattern with alternation
    char combined_pattern[MAX_LINE_LENGTH * MAX_PATTERNS] = "";
    for (i = 0; i < num_patterns; i++) {
        if (i > 0) {
            strcat(combined_pattern, "|");
        }
        strcat(combined_pattern, patterns[i]);
    }

    // Compile the combined regex pattern
    int ret = regcomp(&regex, combined_pattern, REG_EXTENDED);
    if (ret) {
        char err_buf[128];
        regerror(ret, &regex, err_buf, sizeof(err_buf));
        fprintf(stderr, "Error compiling regex: %s\n", err_buf);
        return EXIT_FAILURE;
    }

    // Match each target string against the combined regex pattern
    int count;

    for (i = 0; i < num_targets; i++) {
        // printf("Target: %s\n", targets[i]);
        ret = regexec(&regex, targets[i], 0, NULL, 0);
        if (!ret) {
            count++;
            // printf("  Matched pattern\n");
        } else if (ret == REG_NOMATCH) {
            // printf("  No match found\n");
        } else {
            char err_buf[128];
            regerror(ret, &regex, err_buf, sizeof(err_buf));
            fprintf(stderr, "Error executing regex: %s\n", err_buf);
            return EXIT_FAILURE;
        }
    }
    printf("%i targets out of %i patterns have matched\n",count,num_targets);

    // Free the compiled regex
    regfree(&regex);

    return EXIT_SUCCESS;
}
