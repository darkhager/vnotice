const fs = require('fs');
const path = require('path');

function checkMismatchedBraces(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  const lines = content.split('\n');
  
  const stack = [];
  const pairs = {
    ')': '(',
    '}': '{',
    ']': '['
  };
  
  // Track open quotes to ignore braces inside strings
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTemplateLiteral = false;
  let isCommentLine = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    if (line.trim().startsWith('//')) {
      continue;
    }
    
    for (let col = 0; col < line.length; col++) {
      const char = line[col];
      
      // Handle simple comment skips
      if (char === '/' && line[col + 1] === '/') {
        break; // skip rest of line
      }
      
      // Handle string quote toggles (simple approach)
      if (char === "'" && !inDoubleQuote && !inTemplateLiteral) {
        if (line[col - 1] !== '\\') {
          inSingleQuote = !inSingleQuote;
        }
      } else if (char === '"' && !inSingleQuote && !inTemplateLiteral) {
        if (line[col - 1] !== '\\') {
          inDoubleQuote = !inDoubleQuote;
        }
      } else if (char === '`' && !inSingleQuote && !inDoubleQuote) {
        if (line[col - 1] !== '\\') {
          inTemplateLiteral = !inTemplateLiteral;
        }
      }
      
      if (inSingleQuote || inDoubleQuote || inTemplateLiteral) {
        continue;
      }
      
      if (char === '(' || char === '{' || char === '[') {
        stack.push({ char, line: lineNum, col: col + 1 });
      } else if (char === ')' || char === '}' || char === ']') {
        if (stack.length === 0) {
          console.log(`Extra closing character '${char}' at line ${lineNum}, column ${col + 1}`);
          return;
        }
        
        const top = stack.pop();
        if (pairs[char] !== top.char) {
          console.log(`Mismatched characters: '${top.char}' opened at line ${top.line}, col ${top.col} but closed by '${char}' at line ${lineNum}, col ${col + 1}`);
          return;
        }
      }
    }
  }
  
  if (stack.length > 0) {
    console.log("Unclosed opening characters:");
    // Print the last 5 open tags
    stack.slice(-5).forEach(item => {
      console.log(`  '${item.char}' at line ${item.line}, col ${item.col}`);
    });
  } else {
    console.log("Success: All braces, brackets, and parentheses are perfectly matched!");
  }
}

const targetPath = path.join(__dirname, '..', 'src', 'components', 'Dashboard.tsx');
checkMismatchedBraces(targetPath);
