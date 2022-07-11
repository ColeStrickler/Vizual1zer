import json

running_tests = True



def get_saved_dataset():
    prompt = input("Enter the file path of the saved dataset:")
    f = open(prompt)
    data = json.load(f)
    f.close()
    return data

def save_results(dict, filename):
    new_dict = json.dumps(dict, indent=4)
    with open(filename, "w") as f:
        f.write(new_dict)



def record_test_result(results_value, bool_result):
    if "/" not in results_value:
        results_value = "0/0"
    temp = results_value.split("/")
    first = int(temp[0])
    if bool_result:
        first = int(temp[0]) + 1
    second = int(temp[1]) + 1
    results_value = str(first) + "/" + str(second)
    return results_value




print("[ATOMIC TEST RECORDER]\n\n")
dataset = get_saved_dataset()
while running_tests:
    test_result = ""
    try:
        tactic = input("Enter tactic:")
        technique = input("Enter technique:")
        sub_technique = input("Enter sub-technique or hit [ENTER] if not applicable:")
        while test_result != "True" and test_result != "False":
            test_result = input("Enter test result --> True=Detect, False=Fail to detect:")
        if test_result == "True":
            test_result = True
        elif test_result == "False":
            test_result = False
        if sub_technique == "":
            try:
                print(record_test_result(dataset[tactic][technique]["Test Results"], test_result))
                dataset[tactic][technique]["Test Results"] = record_test_result(dataset[tactic][technique]["Test Results"], test_result)
            except Exception as e:
                dataset[tactic][technique]["Test Results"] = ""
                print(record_test_result(dataset[tactic][technique]["Test Results"], test_result))
                dataset[tactic][technique]["Test Results"] = record_test_result(dataset[tactic][technique]["Test Results"], test_result)
        else:
            try:
                print(record_test_result(dataset[tactic][technique][sub_technique]["Test Results"], test_result))
                dataset[tactic][technique][sub_technique]["Test Results"] = record_test_result(dataset[tactic][technique][sub_technique]["Test Results"], test_result)
            except Exception as e:
                dataset[tactic][technique][sub_technique]["Test Results"] = ""
                print(record_test_result(dataset[tactic][technique][sub_technique]["Test Results"], test_result))
                dataset[tactic][technique][sub_technique]["Test Results"] = record_test_result(dataset[tactic][technique][sub_technique]["Test Results"], test_result)


    except Exception as e:
        print(f"EXCEPTION: {e}\n\nCOULD NOT RECORD RESULT")

    prompt = input("Run another test?(y,n)")
    if prompt == "n":
        running_tests = False

prompt = input("Save progress to output file?(y,n)")

if prompt == "y":
    out_filename = input("Enter the name of the output file:")
    save_results(dataset, out_filename)




