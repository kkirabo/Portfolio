import subprocess

gateway = "192.168.207.254"
remote_ip = "8.8.8.8"
url = "www.google.com"

while True:  # loop until user quits
    print("\nEnter Selection: \n")
    print("        1 - Test connectivity to your gateway.")
    print("        2 - Test for remote connectivity.")
    print("        3 - Test for DNS resolution.")
    print("        4 - Display gateway IP Address.")
    print('        Q/q - Quit program.\n')

    number = input('Please enter a number (1-4) or "Q/q" to quit: ')

    if number.lower() == "q":
        print("Quitting program: returning to terminal. \nHave a wonderful day!")
        break  # exit the loop

    elif number == "1":  # ping gateway
        print("Testing Connectivity to your gateway (192.168.207.254) ...")
        proc = subprocess.Popen(["ping", "-c", "3", gateway])
        print("Running test, please wait.")
        proc.wait()  
        response = proc.returncode
        if response == 0:
            print("Please inform your administrator that the test was SUCCESSFUL!")
        else: 
            print("Please inform your administrator that the test has FAILED!")

    elif number == "2":  # ping remote IP
        print("Testing for remote connectivity... trying IP address 8.8.8.8.")
        proc = subprocess.Popen(["ping", "-c", "3", remote_ip])
        print("Running test, please wait.")
        proc.wait()  
        response = proc.returncode
        if response == 0:
            print("Please inform your administrator that the test was SUCCESSFUL!")
        else: 
            print("Please inform your administrator that the test has FAILED!")

    elif number == "3":  # ping URL
        print("Resolving DNS: trying URL... www.google.com")
        proc = subprocess.Popen(["ping", "-c", "3", url])
        print("Running test, please wait.")
        proc.wait()  
        response = proc.returncode
        if response == 0:
            print("Please inform your administrator that the test was SUCCESSFUL!")
        else: 
            print("Please inform your administrator that the test has FAILED!")

    elif number == "4":  # display gateway
        print("Your gateway IP address is " + gateway)

    else: # invalid input
        print("You entered an invalid option! \nPlease select a number between 1 through 4.")