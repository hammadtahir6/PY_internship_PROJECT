import re

password = input("Enter the password: ")

length_check = len(password) >= 8
upper_check = re.search(r'[A-Z]', password)
lower_check = re.search(r'[a-z]', password)
digit_check = re.search(r'\d', password)
symbol_check = re.search(r'[!@#$%^&*()\-_=+[\]{};:\'",.<>/?\\|`~]', password)

score = sum([bool(length_check),bool(upper_check),bool(lower_check),bool(digit_check),bool(symbol_check)])

if score == 5:
    Strength = "very strong password"
elif score <= 4:
    Strength = 'Strong password'
elif score == 3:
    Strength = "Moderate"
else:
    Strength = "Weak Password"

print(" \n Password Analysis ")
print(f"Length OK: {length_check}")
print(f"Has uppercase: {bool(upper_check)}")
print(f"Has lowercase: {bool(lower_check)}")
print(f"Has digits: {bool(digit_check)}")
print(f"Has symbols: {bool(symbol_check)}")
print(f"Strength = {Strength}")

