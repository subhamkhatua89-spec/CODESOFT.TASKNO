from getpass import getpass

USERNAME = "admin"

username = input("Enter Username: ")
password = getpass("Enter Password: ")

if username == USERNAME and password == "admin123":
    print("Login Successful")
else:
    print("Invalid Username or Password")

filename = input("Enter file name: ")

try:
    with open(filename, "r") as file:
        print(file.read())
except FileNotFoundError:
    print("File not found.")
except PermissionError:
    print("Permission denied.")