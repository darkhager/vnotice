import sys

def check_mismatched_braces(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    stack = []
    pairs = {')': '(', '}': '{', ']': '['}
    
    for i, line in enumerate(lines):
        line_num = i + 1
        # Skip simple comments
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue
            
        for col, char in enumerate(line):
            if char in '({[':
                stack.append((char, line_num, col + 1))
            elif char in ')}]':
                if not stack:
                    print(f"Extra closing character '{char}' at line {line_num}, column {col+1}")
                    return
                top_char, top_line, top_col = stack.pop()
                if pairs[char] != top_char:
                    print(f"Mismatched characters: '{top_char}' opened at line {top_line}, col {top_col} but closed by '{char}' at line {line_num}, col {col+1}")
                    return
                    
    if stack:
        print(f"Unclosed opening characters:")
        for char, line, col in stack[-5:]:
            print(f"  '{char}' at line {line}, col {col}")
    else:
        print("Success: All braces, brackets, and parentheses are perfectly matched!")

if __name__ == '__main__':
    check_mismatched_braces(r"C:\Users\chaiyaphat\cve_monitoring_app\frontend\src\components\Dashboard.tsx")
