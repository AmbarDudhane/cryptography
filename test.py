def rearrane(str):
    temp = list(str)
    output = ""
    i = 0
    checker = ['W', 'D', 'L']
    j = 0
    while True:
        if j == len(checker):
            j = 0

        if checker[j] in temp:
            output += checker[j]
            temp.remove(checker[j])

        elif len(temp) == 0:
            break

        j += 1
    return output



def main():
    s = "LDWDL"
    output = rearrane(s)
    print(output)

if __name__ == "__main__":
    main()