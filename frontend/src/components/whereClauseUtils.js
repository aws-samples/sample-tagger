

export const parseWhereClause = (whereClauseStr) => {
  if (!whereClauseStr || whereClauseStr.trim() === '') return [];
  
  const input = whereClauseStr.trim();
  const result = [];
  let currentIndex = 0;
  
  // Find all conditions by parsing the entire string
  while (currentIndex < input.length) {
    // Skip leading whitespace
    while (currentIndex < input.length && input[currentIndex] === ' ') {
      currentIndex++;
    }
    
    if (currentIndex >= input.length) break;
    
    // Look for json_extract pattern (new syntax)
    const jsonExtractMatch = input.substring(currentIndex).match(
      /json_extract\((\w+),\s*'\$\.([^']+)'\)\s*(IS\s+NOT\s+NULL|IS\s+NULL|!=\s*'([^']*)'|=\s*'([^']*)')/i
    );
    
    // Look for POSITION pattern (legacy syntax)
    const positionMatch = input.substring(currentIndex).match(
      /POSITION\('([^']+)'\s+IN\s+(\w+)\)\s*(>\s*0|=\s*0)/i
    );
    
    // Look for creation_date pattern
    const dateMatch = input.substring(currentIndex).match(
      /creation_date\s*(>=|<=|>|<|=)\s*'([^']*)'/i
    );
    
    // Determine which pattern comes first
    let nextMatch = null;
    let matchType = '';
    let matchIndex = -1;
    
    if (jsonExtractMatch && jsonExtractMatch.index !== undefined) {
      matchIndex = currentIndex + jsonExtractMatch.index;
      nextMatch = jsonExtractMatch;
      matchType = 'json_extract';
    }
    
    if (positionMatch && positionMatch.index !== undefined && 
        (matchIndex === -1 || currentIndex + positionMatch.index < matchIndex)) {
      matchIndex = currentIndex + positionMatch.index;
      nextMatch = positionMatch;
      matchType = 'position';
    }
    
    if (dateMatch && dateMatch.index !== undefined && 
        (matchIndex === -1 || currentIndex + dateMatch.index < matchIndex)) {
      matchIndex = currentIndex + dateMatch.index;
      nextMatch = dateMatch;
      matchType = 'date';
    }
    
    if (!nextMatch) {
      // No more conditions found
      break;
    }
    
    // Find the connector BEFORE this condition (for conditions after the first)
    let connector = '';
    if (result.length > 0) {
      // Look backwards from matchIndex to find AND or OR
      const beforeMatch = input.substring(0, matchIndex).trim();
      if (beforeMatch.endsWith('AND')) {
        connector = 'AND';
      } else if (beforeMatch.endsWith('OR')) {
        connector = 'OR';
      } else {
        // Search for the last occurrence of AND or OR before this match
        const lastAnd = beforeMatch.lastIndexOf(' AND ');
        const lastOr = beforeMatch.lastIndexOf(' OR ');
        if (lastAnd > lastOr) {
          connector = 'AND';
        } else if (lastOr > lastAnd) {
          connector = 'OR';
        } else {
          connector = 'AND'; // Default
        }
      }
    }
    
    // Parse based on match type
    if (matchType === 'json_extract') {
      const field = nextMatch[1];        // tags or metadata
      const key = nextMatch[2];          // JSON key name
      const operator = nextMatch[3];     // IS NOT NULL, IS NULL, = 'value', != 'value'
      const value1 = nextMatch[4];       // Value for !=
      const value2 = nextMatch[5];       // Value for =
      
      let operation, value;
      if (operator.match(/IS\s+NOT\s+NULL/i)) {
        operation = 'KEY_EXISTS';
        value = '';
      } else if (operator.match(/IS\s+NULL/i)) {
        operation = 'KEY_NOT_EXISTS';
        value = '';
      } else if (operator.includes('!=')) {
        operation = 'KEY_NOT_EQUALS';
        value = value1 || '';
      } else if (operator.includes('=')) {
        operation = 'KEY_EQUALS';
        value = value2 || '';
      }
      
      result.push({
        id: `parsed-${Date.now()}-${result.length}-${Math.random().toString(36).substring(2, 9)}`,
        connector: connector,
        field: field,
        operation: operation,
        key: key,
        value: value
      });
      
    } else if (matchType === 'position') {
      // Legacy POSITION syntax - convert to new format
      const searchValue = nextMatch[1];  // The search string
      const field = nextMatch[2];        // tags or metadata
      const comparison = nextMatch[3];   // > 0 or = 0
      
      const operation = comparison.includes('> 0') ? 'KEY_EXISTS' : 'KEY_NOT_EXISTS';
      
      result.push({
        id: `parsed-${Date.now()}-${result.length}-${Math.random().toString(36).substring(2, 9)}`,
        connector: connector,
        field: field,
        operation: operation,
        key: searchValue,  // Use searchValue as key
        value: ''
      });
      
    } else if (matchType === 'date') {
      const operation = nextMatch[1];    // >=, <=, >, <, =
      const dateValue = nextMatch[2];    // Date value
      
      result.push({
        id: `parsed-${Date.now()}-${result.length}-${Math.random().toString(36).substring(2, 9)}`,
        connector: connector,
        field: 'creation_date',
        operation: operation,
        key: '',
        value: dateValue
      });
    }
    
    // Move past this match
    currentIndex = matchIndex + nextMatch[0].length;
  }
  
  return result;
};



// Helper function to generate WHERE clause from conditions
export const generateWhereClause = (conditions) => {
  // For tags/metadata, we need either key or value to be non-empty
  // For creation_date, we need value to be non-empty
  const validConditions = conditions.filter(c => {
    if (c.field === 'creation_date') {
      return c.value && c.value.trim() !== '';
    } else if (c.field === 'metadata' || c.field === 'tags') {
      // For JSON fields, we need at least a key
      const key = c.key || c.value; // Fallback to value for backward compatibility
      return key && key.trim() !== '';
    }
    return false;
  });
  
  if (validConditions.length === 0) {
    return '';
  }
  
  // Generate clauses for conditions with non-empty values
  const validClauses = validConditions.map((condition, index) => {
    const { field, operation, key, value } = condition;
    let clausePart = '';
    
    if (field === 'creation_date') {
      // Handle date comparisons with string format
      clausePart = `${field} ${operation} '${value}'`;
    } else if (field === 'metadata' || field === 'tags') {
      // Use key if available, otherwise fallback to value for backward compatibility
      const jsonKey = key || value;
      const jsonPath = `$.${jsonKey}`;
      
      // Generate JSON extract syntax for SQLite
      switch(operation) {
        case 'KEY_EXISTS':
          clausePart = `json_extract(${field}, '${jsonPath}') IS NOT NULL`;
          break;
        case 'KEY_NOT_EXISTS':
          clausePart = `json_extract(${field}, '${jsonPath}') IS NULL`;
          break;
        case 'KEY_EQUALS':
          if (value && value.trim() !== '') {
            clausePart = `json_extract(${field}, '${jsonPath}') = '${value}'`;
          } else {
            // If no value provided, treat as KEY_EXISTS
            clausePart = `json_extract(${field}, '${jsonPath}') IS NOT NULL`;
          }
          break;
        case 'KEY_NOT_EQUALS':
          if (value && value.trim() !== '') {
            clausePart = `json_extract(${field}, '${jsonPath}') != '${value}'`;
          } else {
            // If no value provided, treat as KEY_NOT_EXISTS
            clausePart = `json_extract(${field}, '${jsonPath}') IS NULL`;
          }
          break;
        // Legacy support for old syntax
        case 'EXISTS':
          clausePart = `json_extract(${field}, '${jsonPath}') IS NOT NULL`;
          break;
        case 'NOT EXISTS':
          clausePart = `json_extract(${field}, '${jsonPath}') IS NULL`;
          break;
        default:
          // Default to KEY_EXISTS
          clausePart = `json_extract(${field}, '${jsonPath}') IS NOT NULL`;
      }
    }
    
    // Add connector for all but the first condition
    return index === 0 ? clausePart : `${condition.connector} ${clausePart}`;
  });

  return validClauses.join(' ');
};

// Field options - common data
export const fieldOptions = [
  { label: 'Creation Date', value: 'creation_date' },
  { label: 'Metadata', value: 'metadata' },
  { label: 'Tags', value: 'tags' }
];

// Operation options by field type
export const operationOptionsByType = {
  'creation_date': [
    { label: 'Greater Than (>)', value: '>' },
    { label: 'Less Than (<)', value: '<' },
    { label: 'Equal (=)', value: '=' }
  ],
  'metadata': [
    { label: 'Key Exists', value: 'KEY_EXISTS' },
    { label: 'Key Not Exists', value: 'KEY_NOT_EXISTS' },
    { label: 'Key Equals Value', value: 'KEY_EQUALS' },
    { label: 'Key Not Equals Value', value: 'KEY_NOT_EQUALS' }
  ],
  'tags': [
    { label: 'Key Exists', value: 'KEY_EXISTS' },
    { label: 'Key Not Exists', value: 'KEY_NOT_EXISTS' },
    { label: 'Key Equals Value', value: 'KEY_EQUALS' },
    { label: 'Key Not Equals Value', value: 'KEY_NOT_EQUALS' }
  ]
};

// Helper to get operation options
export const getOperationOptions = (fieldType) => {
  return operationOptionsByType[fieldType] || [];
};

// Generate tokens from conditions
export const generateTokens = (conditions, fieldOptions, updateCondition, removeCondition) => {
  const tokens = [];
  // For tags/metadata, we need either key or value
  // For creation_date, we need value
  const validConditions = conditions.filter(c => {
    if (c.field === 'creation_date') {
      return c.value && c.value.trim() !== '';
    } else if (c.field === 'metadata' || c.field === 'tags') {
      const key = c.key || c.value; // Fallback for backward compatibility
      return key && key.trim() !== '';
    }
    return false;
  });
  
  validConditions.forEach((condition, index) => {
    // Add connector token except for the first condition
    if (index > 0) {
      tokens.push({
        id: `connector-${condition.id}`,
        value: condition.connector,
        label: condition.connector,
        type: 'connector',
        removable: false,
        onSelect: () => {
          // Toggle between AND and OR when connector is clicked
          if (updateCondition) {
            updateCondition(condition.id, 'connector', condition.connector === 'AND' ? 'OR' : 'AND');
          }
        }
      });
    }

    // Add condition token
    let tokenLabel = '';
    if (condition.field === 'creation_date') {
      // Format date condition
      const operationSymbol = condition.operation;
      const fieldLabel = fieldOptions.find(option => option.value === condition.field)?.label || condition.field;
      tokenLabel = `${fieldLabel} ${operationSymbol} '${condition.value}'`;
    } else if (condition.field === 'metadata' || condition.field === 'tags') {
      // Format metadata/tags condition with new operations
      const operationLabels = {
        'KEY_EXISTS': 'HAS KEY',
        'KEY_NOT_EXISTS': 'MISSING KEY',
        'KEY_EQUALS': 'KEY =',
        'KEY_NOT_EQUALS': 'KEY !=',
        // Legacy support
        'EXISTS': 'HAS KEY',
        'NOT EXISTS': 'MISSING KEY'
      };
      
      const operationLabel = operationLabels[condition.operation] || condition.operation;
      const fieldLabel = fieldOptions.find(option => option.value === condition.field)?.label || condition.field;
      const key = condition.key || condition.value; // Fallback for backward compatibility
      
      if (condition.operation === 'KEY_EQUALS' || condition.operation === 'KEY_NOT_EQUALS') {
        // Show both key and value for comparison operations
        if (condition.value && condition.value.trim() !== '') {
          tokenLabel = `${fieldLabel} ${operationLabel} '${key}' : '${condition.value}'`;
        } else {
          // If no value, just show key existence
          tokenLabel = `${fieldLabel} ${operationLabel} '${key}'`;
        }
      } else {
        // Show only key for existence operations
        tokenLabel = `${fieldLabel} ${operationLabel} '${key}'`;
      }
    }

    tokens.push({
      id: `condition-${condition.id}`,
      value: condition.id,
      label: tokenLabel,
      type: 'condition',
      dismissLabel: "Remove condition",
      onDismiss: removeCondition ? () => removeCondition(condition.id) : undefined
    });
  });
  
  return tokens;
};