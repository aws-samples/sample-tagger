import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Button,
  FormField,
  Grid,
  Select,
  Input,
  SpaceBetween,
  Box,
  Header
} from '@cloudscape-design/components';
import WhereClauseViewer01 from './WhereClauseViewer01';
import {
  parseWhereClause,
  generateWhereClause,
  fieldOptions,
  getOperationOptions
} from './whereClauseUtils';

// Custom equality function for React.memo
function arePropsEqual(prevProps, nextProps) {
  return (
    prevProps.value === nextProps.value && 
    prevProps.readOnly === nextProps.readOnly
    // We intentionally don't compare onChange as it's a function that might change
    // between renders in the parent component
  );
}

const WhereClauseBuilder = React.memo(({ onChange, value = '', readOnly = false }) => {
  // Track if changes originated from this component
  const isInternalChangeRef = useRef(false);
  
  // Track previous value to detect changes
  const prevValueRef = useRef(value);
  
  // Initialize conditions state
  const [conditions, setConditions] = useState([]);
  
  // Debug function to log condition state
  const logConditions = (message, conditionsToLog) => {
    //console.log(message, JSON.stringify(conditionsToLog, null, 2));
  };
  
  // Effect to handle initial value and updates from parent
  useEffect(() => {
    // Skip if this change was initiated from inside the component
    if (isInternalChangeRef.current) {
      isInternalChangeRef.current = false;
      return;
    }
    
    // Only update if value actually changed
    if (prevValueRef.current !== value) {
      prevValueRef.current = value;
      
      const parsedConditions = parseWhereClause(value);
      logConditions("Parsed conditions:", parsedConditions);
      
      if (parsedConditions.length > 0) {
        // Fix the IDs by assigning new unique IDs to each condition
        const fixedConditions = parsedConditions.map((condition, index) => ({
          ...condition,
          id: `fixed-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 9)}`
        }));
        
        setConditions(fixedConditions);
      } else if (!readOnly) {
        // Add a default condition if none exist and not in read-only mode
        setConditions([{
          id: `default-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          field: 'creation_date',
          operation: '>',
          value: '',
          connector: 'AND'
        }]);
      } else {
        setConditions([]);
      }
    }
  }, [value, readOnly]);
  
  // Add default condition if none exist on first render
  useEffect(() => {
    if (conditions.length === 0 && !value && !readOnly) {
      setConditions([{
        id: `default-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        field: 'creation_date',
        operation: '>',
        value: '',
        connector: 'AND'
      }]);
    }
  }, []); // Only run once on mount
  
  // Add new condition
  const addCondition = useCallback(() => {
    setConditions(prevConditions => {
      const newConditions = [
        ...prevConditions,
        {
          id: `new-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          field: 'creation_date',
          operation: '>',
          value: '',
          connector: 'AND'
        }
      ];
      
      // Mark that this change came from inside the component
      isInternalChangeRef.current = true;
      
      // Generate and notify parent component
      const newWhereClause = generateWhereClause(newConditions);
      onChange(newWhereClause);
      prevValueRef.current = newWhereClause;
      
      return newConditions;
    });
  }, [onChange]);

  // Remove condition
  const removeCondition = useCallback((id) => {
    setConditions(prevConditions => {
      // Don't allow removing the last condition
      if (prevConditions.length <= 1) return prevConditions;
      
      const newConditions = prevConditions.filter(condition => condition.id !== id);
      
      // Mark that this change came from inside the component
      isInternalChangeRef.current = true;
      
      // Generate and notify parent component
      const newWhereClause = generateWhereClause(newConditions);
      onChange(newWhereClause);
      prevValueRef.current = newWhereClause;
      
      return newConditions;
    });
  }, [onChange]);

  // Update condition - REVISED APPROACH
  const updateCondition = useCallback((id, property, newValue) => {
    setConditions(prevConditions => {
      logConditions(`Before update for ID ${id}, property ${property}:`, prevConditions);
      
      // Create a completely new array to ensure React detects the change
      const newConditions = prevConditions.map(condition => {
        if (condition.id === id) {
          // Create a completely new object for this condition
          const updatedCondition = { ...condition };
          
          // Update the property
          updatedCondition[property] = newValue;
          
          // Special handling for field changes
          if (property === 'field') {
            updatedCondition.operation = newValue === 'creation_date' ? '>' : 'EXISTS';
            updatedCondition.value = '';
          }
          
          //console.log(`Updated condition ${id}:`, updatedCondition);
          return updatedCondition;
        }
        // Return unmodified conditions as is
        return condition;
      });
      
      logConditions('After update:', newConditions);
      
      // Mark that this change came from inside the component
      isInternalChangeRef.current = true;
      
      // Generate and notify parent component
      const newWhereClause = generateWhereClause(newConditions);
      onChange(newWhereClause);
      prevValueRef.current = newWhereClause;
      
      return newConditions;
    });
  }, [onChange]);
  
  // If in readOnly mode, just show the viewer component
  if (readOnly) {
    return <WhereClauseViewer01 value={value} />;
  }
  
  return (
    <div>
      <SpaceBetween size="l">                
        <Header variant="h3">Build Conditions</Header>
        
        {/* Headers for columns */}
        <Grid gridDefinition={[
          { colspan: 2 },
          { colspan: 3 },
          { colspan: 3 },
          { colspan: 3 },
          { colspan: 1 }
        ]}>
          <div></div>
          <Box fontWeight="bold">Field</Box>
          <Box fontWeight="bold">Operation</Box>
          <Box fontWeight="bold">Value</Box>
          <div></div>
        </Grid>
        
        {conditions.map((condition, index) => (
          <Grid
            key={condition.id}
            gridDefinition={[
              { colspan: 2 },
              { colspan: 3 },
              { colspan: 3 },
              { colspan: 3 },
              { colspan: 1 }
            ]}
          >
            {/* Connector (AND/OR) */}
            {index > 0 ? (
              <FormField label="">
                <Select
                  selectedOption={{ label: condition.connector, value: condition.connector }}
                  onChange={({ detail }) => updateCondition(condition.id, 'connector', detail.selectedOption.value)}
                  options={[
                    { label: 'AND', value: 'AND' },
                    { label: 'OR', value: 'OR' }
                  ]}
                />
              </FormField>
            ) : (
              <div></div> // Empty cell for first row
            )}
            
            {/* Field selection */}
            <FormField label="">
              <Select
                selectedOption={fieldOptions.find(option => option.value === condition.field) || fieldOptions[0]}
                onChange={({ detail }) => updateCondition(condition.id, 'field', detail.selectedOption.value)}
                options={fieldOptions}
                data-testid={`field-select-${index}`}
              />
            </FormField>
            
            {/* Operation selection */}
            <FormField label="">
              <Select
                selectedOption={
                  getOperationOptions(condition.field).find(op => op.value === condition.operation) || 
                  getOperationOptions(condition.field)[0]
                }
                onChange={({ detail }) => updateCondition(condition.id, 'operation', detail.selectedOption.value)}
                options={getOperationOptions(condition.field)}
                data-testid={`operation-select-${index}`}
              />
            </FormField>
            
            {/* Value input */}
            <FormField label="">
              <Input
                value={condition.value || ''}
                onChange={({ detail }) => updateCondition(condition.id, 'value', detail.value)}
                placeholder={condition.field === 'creation_date' 
                  ? "e.g. 2023-04-01 18:00" 
                  : `Enter ${condition.field} value`}
                data-testid={`value-input-${index}`}
              />
            </FormField>
            
            {/* Remove condition button */}
            <Button 
              iconName="remove"
              onClick={() => removeCondition(condition.id)}
              variant="icon"
              disabled={conditions.length <= 1}
              ariaLabel="Remove condition"
              data-testid={`remove-button-${index}`}
            />
          </Grid>
        ))}
        
        {/* Add condition button */}
        <div>
          <Button 
            onClick={addCondition}
            iconName="add-plus"
            data-testid="add-condition-button"
          >
            Add Condition
          </Button>
        </div>
      </SpaceBetween>
    </div>
  );
}, arePropsEqual);

export default WhereClauseBuilder;