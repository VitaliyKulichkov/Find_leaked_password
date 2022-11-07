import hashlib
from pathlib import Path


# Function to read files
def read_file(filename):
    res = [w for w in Path(filename).read_text(encoding="utf-8").replace("\n", " ").split()]
    return res

# If we r using 1 string password
def one_password_to_list():
    str = input("Введите ваш пароль для проверки: ")
    return list(str.split())


# Variable, choose hash type (md5 or sha1)
hash_type = "sha1"


# Function to hash passwords
def create_hash_md5_text_file(input_list, hash_type):
    input_list = list(map(str.strip, input_list))  # delete \n
    hashes_to_export = []

    # loop through the words in the input list
    for word in input_list:
        if hash_type == "md5":
            crypt = hashlib.md5()
        elif hash_type == "sha1":
            crypt = hashlib.sha1()
        crypt.update(bytes(word, encoding='utf-8'))

        hash_of_word = crypt.hexdigest()
        hashes_to_export.append(hash_of_word)

    return hashes_to_export


# Function to create dict from 2 lists
def create_dict(list1, list2):
    result = dict(zip(list1, list2))
    return result


# Function to create list from dict.values
def create_lst(lst):
    return list(lst)


# Function to check is our hashed password equals leaked hashed passwords
def lst_leak_or_not(lst1, lst2):
    leaked_val = (set(lst1) & set(lst2))
    not_leaked = set(lst1) - set(lst2)
    return leaked_val, not_leaked


# Function to get keys of a dict using values and
# changing value for 'leaked' if password leaked or 'not leaked' if password not leaked
def get_key(dict_password_to_check, values):
    for k, v in dict_password_to_check.items():
        if v in values:
            dict_password_to_check[k] = 'LEAKED!'
        else:
            dict_password_to_check[k] = 'NOT LEAKED'


# Creating new file (can replace our start file with passwords)
# and showing passwords with caption "leaked" or "not leaked"
def wr_out_file(filename, dict_items):
    with open(filename, 'w') as out:
        for key, val in dict_items:
            out.write('{}:{}\n'.format(key, val))


# main func
def main():
    # password_to_check = one_password_to_list()
    # uncomment line 77 if u want to check only 1 password
    # reading files (use 1MillionPasswords.txt, can also use my test_file.txt)
    password_to_check = read_file('passwords.txt')
    password_to_guess = read_file('1MillionPasswords.txt')
    # Creating list of hashed passwords создаем список хэшированных паролей
    hashed_pass_to_check = create_hash_md5_text_file(password_to_check, hash_type)
    hashed_pass_leaked = create_hash_md5_text_file(password_to_guess, hash_type)

    # Creating dict`s
    dict_password_to_guess = create_dict(password_to_guess, hashed_pass_leaked)
    dict_password_to_check = create_dict(password_to_check, hashed_pass_to_check)

    # Creating lists with hashed passwords to compare it
    lst_check = create_lst(dict_password_to_check.values())
    lst_leaked = create_lst(dict_password_to_guess.values())

    # List with leaked values and not leaked values of dict of passwords which we`r checking
    leaked_val = lst_leak_or_not(lst_check, lst_leaked)[0]
    # not_leaked = lst_leak_or_not(lst_check, lst_leaked)[1] if u need not leaked hashed passwords

    # Finding keys of our dictionary by using list leaked_val with leaked hashed passwords
    # and changing value of the dictionary to 'Leaked!' or 'Not leaked'
    get_key(dict_password_to_check, leaked_val)

    # Creating new or rewriting our file and now we have an inscription opposite each password "leaked" or "not leaked"
    wr_out_file('leaks.txt', dict_password_to_check.items())


if __name__ == "__main__":
    main()
