// Helper function to parse WHERE clause string into conditions
export const parseWhereClause = (whereClauseStr) => {
  if (!whereClauseStr || whereClauseStr.trim() === '') return [];
  
  const input = whereClauseStr.trim();
  const result = [];
  let currentIndex = 0;
  
  // Find all conditions by parsing the entire string
  while (currentIndex < input.length) {
    // Find the next condition starting from currentIndex
    
    // Look for metadata condition
    const metadataIndex = input.indexOf("POSITION(", currentIndex);
    const metadataInIndex = input.indexOf("IN metadata", currentIndex);
    
    // Look for tags condition
    const tagsIndex = input.indexOf("IN tags", currentIndex);
    
    // Look for creation_date condition
    const dateIndex = input.indexOf("creation_date", currentIndex);
    
    // Determine which condition comes first
    let nextConditionIndex = -1;
    let conditionType = '';
    
    if (metadataIndex !== -1 && metadataInIndex !== -1 && 
        metadataIndex < metadataInIndex &&
        (nextConditionIndex === -1 || metadataIndex < nextConditionIndex)) {
      nextConditionIndex = metadataIndex;
      conditionType = 'metadata';
    }
    
    if (tagsIndex !== -1 && 
        tagsIndex > currentIndex &&
        (nextConditionIndex === -1 || input.indexOf("POSITION(", currentIndex) < nextConditionIndex)) {
      nextConditionIndex = input.indexOf("POSITION(", currentIndex);
      conditionType = 'tags';
    }
    
    if (dateIndex !== -1 &&
        (nextConditionIndex === -1 || dateIndex < nextConditionIndex)) {
      nextConditionIndex = dateIndex;
      conditionType = 'creation_date';
    }
    
    if (nextConditionIndex === -1) {
      // No more conditions found
      break;
    }
    
    // Find the end of this condition
    let endIndex = input.length;
    
    // Look for AND/OR after this condition
    const nextAnd = input.indexOf(" AND ", nextConditionIndex);
    const nextOr = input.indexOf(" OR ", nextConditionIndex);
    
    if (nextAnd !== -1 && (nextOr === -1 || nextAnd < nextOr)) {
      endIndex = nextAnd;
    } else if (nextOr !== -1) {
      endIndex = nextOr;
    }
    
    // Get the condition text
    const conditionText = input.substring(nextConditionIndex, endIndex);
    
    // Parse the condition based on its type
    if (conditionType === 'metadata') {
      // Find the metadata value inside quotes
      const startQuote = conditionText.indexOf("'");
      const endQuote = conditionText.indexOf("'", startQuote + 1);
      
      if (startQuote !== -1 && endQuote !== -1) {
        const metadataValue = conditionText.substring(startQuote + 1, endQuote);
        const isExists = conditionText.includes("> 0");
        const operation = isExists ? 'EXISTS' : 'NOT EXISTS';
        
        // Determine connector
        let connector = 'AND';
        if (result.length > 0) {
          // Look backward for connector
          const beforeText = input.substring(0, nextConditionIndex).trim();
          if (beforeText.endsWith("OR")) {
            connector = 'OR';
          }
        }
        
        result.push({
          id: `parsed-${Date.now()}-${result.length}`,
          connector: connector,
          field: 'metadata',
          operation: operation,
          value: metadataValue
        });
      }
    } else if (conditionType === 'tags') {
      // Find the tags value inside quotes
      const startQuote = conditionText.indexOf("'");
      const endQuote = conditionText.indexOf("'", startQuote + 1);
      
      if (startQuote !== -1 && endQuote !== -1) {
        const tagsValue = conditionText.substring(startQuote + 1, endQuote);
        const isExists = conditionText.includes("> 0");
        const operation = isExists ? 'EXISTS' : 'NOT EXISTS';
        
        // Determine connector
        let connector = 'AND';
        if (result.length > 0) {
          // Look backward for connector
          const beforeText = input.substring(0, nextConditionIndex).trim();
          if (beforeText.endsWith("OR")) {
            connector = 'OR';
          }
        }
        
        result.push({
          id: `parsed-${Date.now()}-${result.length}`,
          connector: connector,
          field: 'tags',
          operation: operation,
          value: tagsValue
        });
      }
    } else if (conditionType === 'creation_date') {
      // Extract operation
      let operation = '';
      if (conditionText.includes(">")) {
        operation = '>';
      } else if (conditionText.includes("<")) {
        operation = '<';
      } else if (conditionText.includes("=")) {
        operation = '=';
      }
      
      // Extract the date value inside quotes
      const startQuote = conditionText.indexOf("'");
      const endQuote = conditionText.indexOf("'", startQuote + 1);
      
      if (startQuote !== -1 && endQuote !== -1 && operation) {
        const dateValue = conditionText.substring(startQuote + 1, endQuote);
        
        // Determine connector
        let connector = 'AND';
        if (result.length > 0) {
          // Look backward for connector
          const beforeText = input.substring(0, nextConditionIndex).trim();
          if (beforeText.endsWith("OR")) {
            connector = 'OR';
          }
        }
        
        result.push({
          id: `parsed-${Date.now()}-${result.length}`,
          connector: connector,
          field: 'creation_date',
          operation: operation,
          value: dateValue
        });
      }
    }
    
    // Move to the next part of the string
    currentIndex = endIndex > nextConditionIndex ? endIndex : nextConditionIndex + 1;
  }
  
  return result;
};

// Helper function to generate WHERE clause from conditions
export const generateWhereClause = (conditions) => {
  const validConditions = conditions.filter(c => c.value && c.value.trim() !== '');
  
  if (validConditions.length === 0) {
    return '';
  }
  
  // Generate clauses for conditions with non-empty values
  const validClauses = validConditions.map((condition, index) => {
    const { field, operation, value } = condition;
    let clausePart = '';
    
    if (field === 'creation_date') {
      // Handle date comparisons with string format
      clausePart = `${field} ${operation} '${value}'`;
    } else if (field === 'metadata' || field === 'tags') {
      // Handle string EXISTS/NOT EXISTS
      if (operation === 'EXISTS') {
        clausePart = `POSITION('${value}' IN ${field}) > 0`;
      } else {
        clausePart = `POSITION('${value}' IN ${field}) = 0`;
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
    { label: 'CONTAINS', value: 'EXISTS' },
    { label: 'NOT CONTAINS', value: 'NOT EXISTS' }
  ],
  'tags': [
    { label: 'CONTAINS', value: 'EXISTS' },
    { label: 'NOT CONTAINS', value: 'NOT EXISTS' }
  ]
};

// Helper to get operation options
export const getOperationOptions = (fieldType) => {
  return operationOptionsByType[fieldType] || [];
};

// Generate tokens from conditions
export const generateTokens = (conditions, fieldOptions, updateCondition, removeCondition) => {
  const tokens = [];
  const validConditions = conditions.filter(c => c.value && c.value.trim() !== '');
  
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
      // Format metadata/tags condition
      const operationLabel = condition.operation === 'EXISTS' ? 'CONTAINS' : 'NOT CONTAINS';
      const fieldLabel = fieldOptions.find(option => option.value === condition.field)?.label || condition.field;
      tokenLabel = `${fieldLabel} ${operationLabel} '${condition.value}'`;
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