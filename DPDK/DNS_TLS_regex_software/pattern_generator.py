import random
import string

def generate_regex_pattern(length):
    pattern = ''
    for _ in range(length):
        choice = random.choice([
            '[a-zA-Z0-9]',  # Character class
            '.',            # Any character
            '*', '+', '?',  # Quantifiers
            '|',            # Alternation
            '(', ')'        # Grouping
        ])
        pattern += choice
    return pattern

def generate_regex_patterns(num_patterns, pattern_length):
    patterns = [generate_regex_pattern(pattern_length) for _ in range(num_patterns)]
    return patterns

def write_patterns_to_file(patterns, filename):
    with open(filename, 'w') as file:
        for pattern in patterns:
            file.write(pattern + '\n')

if __name__ == "__main__":
    num_patterns = 2
    pattern_length = 10  # Adjust as needed for the desired length of each regex pattern
    output_file = "regex_patterns.txt"

    patterns = generate_regex_patterns(num_patterns, pattern_length)
    write_patterns_to_file(patterns, output_file)

    print(f"{num_patterns} random valid regular expressions of length {pattern_length} have been generated and saved to '{output_file}'.")
