#main python script
import csv
import checklist1
import inspect

check_functions = [
    (name, obj) for name, obj in inspect.getmembers(checklist1)
    if inspect.isfunction(obj) and name.startswith("check_")
    
]

numb_of_checks = len(check_functions)


with open("result.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Check Name", "Result"])

    for name, func in check_functions:
        try:
            result = func()
            writer.writerow([name, "Pass", if result else "Fail"])
        except Exception as e:
            writer.writerow ([name, f"Error: {str(e)}"])



















