import bcrypt
import hashlib
import time
import argon2

def bcrypt_hash(password, rounds=12):
    salt = bcrypt.gensalt(rounds=rounds)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def md5_hash(password):
    hashed_password = hashlib.md5(password.encode('utf-8')).hexdigest()
    return hashed_password

def sha1_hash(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    return hashed_password

def argon2_hash(password):
    hasher = argon2.PasswordHasher()
    hashed_password = hasher.hash(password)
    return hashed_password


def hmac_hash(password, key, hash_algorithm='sha256'):
    import hmac
    hashed_password = hmac.new(key.encode('utf-8'), password.encode('utf-8'), hash_algorithm).hexdigest()
    return hashed_password

def main():
    password = input("Wprowadź hasło: ")
    algorithm_choice = input("Wybierz algorytm (bcrypt/md5/sha1/argon2/hmac): ")

    start_time = time.time()

    if algorithm_choice == 'bcrypt':
        hashed_password = bcrypt_hash(password)
    elif algorithm_choice == 'md5':
        hashed_password = md5_hash(password)
    elif algorithm_choice == 'sha1':
        hashed_password = sha1_hash(password)
    elif algorithm_choice == 'argon2':
        hashed_password = argon2_hash(password)
    elif algorithm_choice == 'hmac':
        key = input("Wprowadź klucz dla HMAC: ")
        hashed_password = hmac_hash(password, key)
    else:
        print("Niepoprawny wybór algorytmu.")
        return

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("Wygenerowany hasz: ", hashed_password)
    print("Czas generowania hasha: {:.20f} sekund".format(elapsed_time))

if __name__ == "__main__":
    main()
