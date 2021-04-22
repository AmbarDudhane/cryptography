"""
Reference: https://www.geeksforgeeks.org/compare-two-files-using-hashing-in-python/
"""
import hashlib


class HashGenerator:

    def hashfile(self, filename):
        print("In hashfile")
        BUF_SIZE = 65536

        # Initializing the sha256() method
        sha256 = hashlib.sha256()

        # Opening the file provided as
        # the first commandline arguement
        with open(filename, 'rb') as f:

            while True:
                data = f.read(BUF_SIZE)

                # True if eof = 1
                if not data:
                    break

                # Passing that data to that sh256 hash
                # function (updating the function with
                # that data)
                sha256.update(data)
        print("Hashing complete")
        return sha256.hexdigest()

    def comparehash(self, hash1, hash2):
        if hash1 == hash2:
            print("Both files are same")

        else:
            print("Files are different!")
