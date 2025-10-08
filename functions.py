# Declares a function to convert number output into a swedish format

def swedish_number_strings_to_float(string):
    try:
        return float(string.replace(" ","").replace(",","."))
    
    except:
        return 0