import random
import string

def generate_random_string():
    length = random.randint(5, 10)
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def generate_and_store_random_strings(num_strings, output_file):
    with open(output_file, 'w') as file:
        for i in range(num_strings):
            random_string = generate_random_string()
            random_string2 = generate_random_string()
            random_string = str(i) + ", /([a-z]|[A-Z]|[0-9])+" + random_string + "([a-z]|[A-Z]|[0-9])+"+random_string2+"/"
            file.write(random_string + '\n')

if __name__ == "__main__":
    num_strings = 15000
    output_file = "random_strings_ternary.txt"

    generate_and_store_random_strings(num_strings, output_file)
    print(f"{num_strings} random strings of length have been written to '{output_file}'.")
