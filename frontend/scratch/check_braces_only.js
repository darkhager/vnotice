const fs = require('fs');
const path = require('path');

function checkBracesOnly(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  const lines = content.split('\n');
  
  const stack = [];
  
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTemplateLiteral = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    if (line.trim().startsWith('//')) {
      continue;
    }
    
    for (let col = 0; col < line.length; col++) {
      const char = line[col];
      
      // Comments skip
      if (char === '/' && line[col + 1] === '/') {
        break; 
      }
      
      // Handle strings
      if (char === "'" && !inDoubleQuote && !inTemplateLiteral) {
        if (line[col - 1] !== '\\') inSingleQuote = !inSingleQuote;
      } else if (char === '"' && !inSingleQuote && !inTemplateLiteral) {
        if (line[col - 1] !== '\\') inDoubleQuote = !inDoubleQuote;
      } else if (char === '`' && !inSingleQuote && !inDoubleQuote) {
        if (line[col - 1] !== '\\') inTemplateLiteral = !inTemplateLiteral;
      }
      
      if (inSingleQuote || inDoubleQuote || inTemplateLiteral) {
        continue;
      }
      
      if (char === '{') {
        stack.push({ char, line: lineNum, col: col + 1 });
      } else if (char === '}') {
        if (stack.length === 0) {
          console.log(`Extra closing brace '}' at line ${lineNum}, column ${col + 1}`);
          return;
        }
        stack.pop();
      }
    }
  }
  
  if (stack.length > 0) {
    console.log("Unclosed opening braces:");
    stack.forEach(item => {
      console.log(`  '{' at line ${item.line}, col ${item.col}`);
    });
  } else {
    console.log("Success: All curly braces are perfectly matched!");
  }
}

const targetPath = path.join(__dirname, '..', 'src', 'components', 'Dashboard.tsx');
checkBracesOnly(targetPath);
