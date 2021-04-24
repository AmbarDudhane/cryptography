import sys

def divideintochunks(str):
    chunk_size = 256
    chunks = []
    i = 0
    while i < len(str):
        if i + chunk_size < len(str):
            chunks.append(str[i:i + chunk_size])
        else:
            chunks.append(str[i:len(str)])
        i += chunk_size

    # if last block is less than chunk size, pad it with 0
    lastBlock = chunks[-1]
    if len(lastBlock) < chunk_size:
        diff = chunk_size - len(lastBlock)
        for i in range(diff):
            chunks[-1] = chunks[-1] + "0"
    print("Length of chunks:", len(chunks))
    print(chunks)



def main():
    f = open("C://Users//Ambar//OneDrive//Desktop//abcdef.txt", "r")
    s = f.read()
    print("String Bytes:", sys.getsizeof(s))
    print("String len:", len(s))
    divideintochunks(s)
    # print(output)

if __name__ == "__main__":
    main()